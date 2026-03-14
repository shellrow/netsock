use std::collections::HashMap;

use crate::error::*;
use crate::socket::SocketInfo;
use crate::sys::windows::socket_table_extended::SocketTable;

pub struct SocketTableIterator {
    table: Vec<u8>,
    rows_count: usize,
    current_row_index: usize,
    process_names: Option<HashMap<u32, String>>,
    info_getter: fn(&[u8], usize, Option<&HashMap<u32, String>>) -> SocketInfo,
}

impl SocketTableIterator {
    pub fn new<Table: SocketTable>() -> Result<Self, Error> {
        let table = Table::get_table()?;
        Ok(SocketTableIterator {
            rows_count: Table::get_rows_count(&table),
            process_names: Table::get_process_names().ok(),
            info_getter: Table::get_socket_info,
            current_row_index: 0,
            table,
        })
    }
}

impl Iterator for SocketTableIterator {
    type Item = Result<SocketInfo, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_row_index == self.rows_count {
            None
        } else {
            let socket_info = (self.info_getter)(
                &self.table,
                self.current_row_index,
                self.process_names.as_ref(),
            );
            self.current_row_index += 1;
            Some(Ok(socket_info))
        }
    }
}
