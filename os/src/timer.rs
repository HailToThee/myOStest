use riscv::register::time;
use crate::config::CLOCK_FREQ;

const MICRO_PER_SEC: usize = 1_000_000;
pub fn sleep_us(us: usize) {
    let time = time::read();
    while time::read() - time < us*(CLOCK_FREQ / MICRO_PER_SEC) {}
}