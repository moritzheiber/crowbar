use std::{
    io::{stderr, stdout, Write},
    process,
};

pub fn print_causes(e: impl Into<anyhow::Error>, mut w: impl Write) {
    let e = e.into();
    let causes = e.chain().collect::<Vec<_>>();
    let num_causes = causes.len();
    for (index, cause) in causes.iter().enumerate() {
        if index == 0 {
            writeln!(w, "{}", cause).ok();
            if num_causes > 1 {
                writeln!(w, "Caused by: ").ok();
            }
        } else {
            writeln!(w, " {}: {}", num_causes - index, cause).ok();
        }
    }
}

pub fn ok_or_exit<T, E>(r: Result<T, E>) -> T
where
    E: Into<anyhow::Error>,
{
    match r {
        Ok(r) => r,
        Err(e) => {
            stdout().flush().ok();
            print_causes(e, stderr());
            process::exit(1);
        }
    }
}
