#[macro_use]
extern crate arrayref;
extern crate arrayvec;
extern crate blake2b_simd;
extern crate byteorder;
extern crate crossbeam;
extern crate num_cpus;
extern crate rayon;

#[cfg(test)]
#[macro_use]
extern crate duct;
#[cfg(test)]
extern crate hex;

pub mod decode;
pub mod encode;
pub mod hash;

#[cfg(test)]
mod test {
    use std::process::Command;

    #[test]
    fn run_python_tests() {
        let output = Command::new("python3")
            .arg("./python/test.py")
            .output()
            .expect("Python test script failed to run.");
        println!(
            "=== stdout ===\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        println!(
            "=== stderr ===\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "Python tests failed.");
    }
}
