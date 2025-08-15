use windows::core::w;
use windows::Win32::Foundation::{GetLastError, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Console::{GetConsoleMode, SetConsoleMode, CONSOLE_MODE};

#[cfg(target_os = "windows")]
pub fn enable_ansi_support() -> anyhow::Result<()> {
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    unsafe {
        let console_handle = CreateFileW(
            w!("CONOUT$"),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES::default(),
            None,
        )?;
        if console_handle == INVALID_HANDLE_VALUE {
            GetLastError().ok()?;
        }
        let mut console_mode = CONSOLE_MODE::default();
        GetConsoleMode(console_handle, &mut console_mode)?;
        if console_mode.0 & ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
            SetConsoleMode(
                console_handle,
                CONSOLE_MODE(console_mode.0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING),
            )?;
        }
    }
    Ok(())
}
