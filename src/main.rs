use async_std::task::block_on;
use pdf::{
    self,
    error::PdfError,
    object::{Object, Ref, Resolve, Stream},
    primitive::{Dictionary, PdfString, Primitive},
};
use pdf_derive::Object;
use std::{
    convert::TryInto,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::PathBuf,
    rc::Rc,
};

// "Foxit Approved Trust List"
const URL: &str =
    "http://cdn01.foxitsoftware.com/pub/foxit/addonservice/certs/phantom/cer.pdf";
const FILENAME: &str = "cer.pdf";
const PASSWORD: &[u8] = b"phantomkey";
const OUTPUT_DIRECTORY: &str = "certificates";

#[derive(Debug, Object)]
struct Trailer {
    #[pdf(key = "Root")]
    root: Catalog,
}

#[derive(Debug, Object)]
struct Catalog {
    #[pdf(key = "Pages")]
    pages: PagesNode,
}

#[derive(Debug)]
enum PagesNode {
    Tree(Rc<PageTree>),
    Leaf(Rc<Page>),
}

impl Object for PagesNode {
    fn serialize<W: io::Write>(&self, out: &mut W) -> Result<(), PdfError> {
        match *self {
            PagesNode::Tree(ref t) => t.serialize(out),
            PagesNode::Leaf(ref l) => l.serialize(out),
        }
    }

    fn from_primitive(p: Primitive, r: &impl Resolve) -> Result<PagesNode, PdfError> {
        let dict = Dictionary::from_primitive(p, r)?;
        match dict["Type"].as_name()? {
            "Page" => Ok(PagesNode::Leaf(Object::from_primitive(
                Primitive::Dictionary(dict),
                r,
            )?)),
            "Pages" => Ok(PagesNode::Tree(Object::from_primitive(
                Primitive::Dictionary(dict),
                r,
            )?)),
            other => Err(PdfError::WrongDictionaryType {
                expected: "Page or Pages".into(),
                found: other.into(),
            }),
        }
    }
}

#[derive(Debug, Object)]
struct PageTree {
    #[pdf(key = "Kids")]
    kids: Vec<Ref<PagesNode>>,
}

#[derive(Debug, Object)]
struct Page {
    #[pdf(key = "CertData")]
    cert_data: Option<Stream<CertData>>,
}

#[derive(Debug, Object)]
struct CertData {
    /// So far, always true
    #[pdf(key = "CertifyDoc")]
    certify_doc: bool,

    /// Hex-encoded serial number of the certificate for this certificate's issuer
    #[pdf(key = "ChainParentSn")]
    chain_parent_sn: PdfString,

    /// So far, always true
    #[pdf(key = "TrustedRoot")]
    trusted_root: bool,

    /// So far, always true
    #[pdf(key = "SignDoc")]
    sign_doc: bool,
}

trait PageVisitor {
    fn visit_page(&mut self, page: &Page);
    fn visit_tree(&mut self, tree: &PageTree);

    fn walk_pages<R: Resolve>(&mut self, node: &PagesNode, resolve: &R) -> Result<(), PdfError> {
        match node {
            PagesNode::Tree(tree) => {
                self.visit_tree(tree);
                for node in tree.kids.iter() {
                    self.walk_pages(&*resolve.get(*node)?, resolve)?;
                }
            }
            PagesNode::Leaf(page) => self.visit_page(page),
        }
        Ok(())
    }
}

struct CertificatePageVisitor<F: FnMut(&Stream<CertData>)>(F);

impl<F: FnMut(&Stream<CertData>)> CertificatePageVisitor<F> {
    fn new(callback: F) -> CertificatePageVisitor<F> {
        CertificatePageVisitor(callback)
    }
}

impl<F: FnMut(&Stream<CertData>)> PageVisitor for CertificatePageVisitor<F> {
    fn visit_page(&mut self, page: &Page) {
        if let Some(cert_data) = &page.cert_data {
            self.0(cert_data);
        }
    }

    fn visit_tree(&mut self, _tree: &PageTree) {}
}

fn main() {
    let path = PathBuf::from(FILENAME);

    let data = block_on(async {
        let mut result = surf::get(URL).await?;
        result.body_bytes().await
    })
    .expect("error downloading file");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)
            .expect("couldn't create file");
        file.write_all(&data).expect("couldn't write to PDF file");
        file.flush().expect("couldn't finish writing to PDF file");
    }

    let mut data = vec![];
    OpenOptions::new()
        .read(true)
        .open(&path)
        .expect("couldn't open PDF file")
        .read_to_end(&mut data)
        .expect("error reading PDF file");

    let (storage, trailer) = pdf::file::load_storage_and_trailer_password(data, PASSWORD)
        .expect("error loading PDF file");
    let trailer = Trailer::from_primitive(Primitive::Dictionary(trailer), &storage)
        .expect("error loading PDF objects");

    let directory = PathBuf::from(OUTPUT_DIRECTORY);
    if directory.is_dir() {
        fs::remove_dir_all(&directory).expect("couldn't clear output directory");
    }
    fs::create_dir(&directory).expect("couldn't create output directory");

    let mut counter = 1;
    let mut visitor = CertificatePageVisitor::new(|cert_data| {
        let stream_data = cert_data.data().expect("error reading stream data");
        let (header_data, der_data) = stream_data.split_at(12);

        // always 0x20
        let _header_dword_1 = u32::from_le_bytes(header_data[..4].try_into().unwrap());

        // always 1
        let _header_dword_2 = u32::from_le_bytes(header_data[4..8].try_into().unwrap());

        // always the length of the DER-encoded certificate
        let _header_dword_3 = u32::from_le_bytes(header_data[8..12].try_into().unwrap());

        if let Ok(parsed) = openssl::x509::X509::from_der(der_data) {
            println!("{:?}", parsed.subject_name());
        } else {
            println!("Unparseable certificate");
        }

        println!("{:#?}", cert_data);

        {
            let mut certificate_file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(directory.join(format!("{}.crt", counter)))
                .expect("couldn't create certificate output file");
            counter += 1;
            certificate_file
                .write_all(der_data)
                .expect("couldn't write to certificate output file");
            certificate_file
                .flush()
                .expect("couldn't finish writing to certificate output file");
        }

        let encoded = base64::encode(der_data);
        println!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            encoded
        );
        println!();
    });
    visitor
        .walk_pages(&trailer.root.pages, &storage)
        .expect("error while reading PDF pages");
}
