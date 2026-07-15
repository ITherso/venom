use crate::Result;

pub struct Database;

impl Database {
    pub fn init(_path: &str) -> Result<()> {
        println!("[+] Database initialized");
        Ok(())
    }
}
