use crate::crypto::cipher_types::{CipherInput, CipherOutput};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};

pub fn read_all(input: &CipherInput) -> io::Result<Vec<u8>> {
    match input {
        CipherInput::Bytes(data) => Ok(data.clone()),
        CipherInput::File(path) => {
            let mut reader = BufReader::new(File::open(path)?);
            let mut buffer = Vec::new();
            reader.read_to_end(&mut buffer)?;
            Ok(buffer)
        }
    }
}

pub fn write_all(output: &mut CipherOutput, data: &[u8]) -> io::Result<()> {
    match output {
        CipherOutput::Buffer(buffer) => {
            buffer.clear();
            buffer.extend_from_slice(data);
            Ok(())
        }
        CipherOutput::File(path) => {
            let mut writer = BufWriter::new(File::create(path)?);
            writer.write_all(data)?;
            Ok(())
        }
    }
}

/// Поблочное чтение из файла с обработкой блока
pub fn read_blockwise_with_end<F>(
    path: &str,
    block_size: usize,
    mut handle_block: F,
) -> io::Result<()>
where
    F: FnMut(&[u8], bool) -> io::Result<()>,
{
    let mut reader = BufReader::new(File::open(path)?);
    let mut prev_block = Vec::new();
    let mut buffer = vec![0u8; block_size];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            if !prev_block.is_empty() {
                handle_block(&prev_block, true)?;
            }
            break;
        }

        if !prev_block.is_empty() {
            handle_block(&prev_block, false)?;
        }

        prev_block = buffer[..read].to_vec();
    }

    Ok(())
}

/// Поблочная запись в файл
pub fn write_blockwise(path: &str, blocks: &[Vec<u8>]) -> io::Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    for block in blocks {
        writer.write_all(block)?;
    }
    Ok(())
}
