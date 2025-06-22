macro_rules! check_is_file {
    ($x:expr) => {
        if !$x.exists() || !$x.is_file() {
            return Err(anyhow::anyhow!(
                "Path '{}' does not exist or is not a file",
                $x.display()
            ));
        }
    };
    ($x:expr, $($xs:expr),+) => {
        if !$x.exists() || !$x.is_file() {
            return Err(anyhow::anyhow!(
                "Path '{}' does not exist or is not a file",
                $x.display()
            ));
        }
        
        check_is_file!($($xs),+);
    };
}


pub(crate) use check_is_file;

macro_rules! check_is_dir {
    ($x:expr) => {
        if !$x.exists() || !$x.is_dir() {
            return Err(anyhow::anyhow!(
                "Path '{}' does not exist or is not a file",
                $x.display()
            ));
        }
    };
    ($x:expr, $($xs:expr),+) => {
        if !$x.exists() || !$x.is_dir() {
            return Err(anyhow::anyhow!(
                "Path '{}' does not exist or is not a file",
                $x.display()
            ));
        }

        check_is_dir!($($xs),+);
    };
}


pub(crate) use check_is_dir;
