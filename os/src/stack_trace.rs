use core::{arch::asm, ptr};

pub unsafe fn print_stack_trace() -> () {
    let mut fp: *const usize;
    unsafe {
        asm!("mv {},fp", out(reg) fp);
    }

    println!("== Begin stack trace ==");
    while fp != ptr::null() {
        let saved_ra = unsafe { *fp.sub(1) };
        let saved_fp = unsafe { *fp.sub(2) };

        println!("0x{:016x}, fp = 0x{:016x}", saved_ra, saved_fp);

        fp = saved_fp as *const usize;
    }
    println!("== End stack trace ==");
}
/*
+----------------+
| ...            |
+----------------+
| 保存的返回地址  |  <-- fp-1
+----------------+
| 保存的帧指针    |  <-- fp-2
+----------------+
| ...            |
+----------------+
 */
