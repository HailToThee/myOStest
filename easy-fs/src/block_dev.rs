use core::any::Any;
/// Trait for block devices
/// which reads and writes data in the unit of blocks
pub trait BlockDevice: Send + Sync + Any {
    ///Read data form block to buffer
    fn read_block(&self, block_id: usize, buf: &mut [u8]);
    ///Write data from buffer to block
    fn write_block(&self, block_id: usize, buf: &[u8]);
    //Send:如果一个类型实现了 Send，这意味着该类型的实例可以安全地跨线程边界发送
    //Sync:如果一个类型实现了 Sync，这意味着该类型的实例可以安全地在多个线程中共享
    //Any:如果一个类型实现了 Any，这意味着该类型可以在运行时进行类型检查和转换
}
