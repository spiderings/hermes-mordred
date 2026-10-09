use std::io::{self, Write};
use std::process::ExitCode;
#[cfg(windows)]
use winkey_helper::cng::CngOps as PlatformOps;
#[cfg(not(windows))]
use winkey_helper::ops::UnavailableOps as PlatformOps;
use winkey_helper::wire::{dispatch, read_request, Response};
use zeroize::Zeroize;

fn main() -> ExitCode {
    let response = match read_request(io::stdin().lock()) {
        Ok(request) => dispatch(request, &mut PlatformOps),
        Err(error) => Response::from_error(error),
    };
    let failed = response.is_error();
    let mut output = response.to_json();
    output.push('\n');
    let written = io::stdout().lock().write_all(output.as_bytes());
    output.zeroize();
    if failed || written.is_err() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
