//!Implementation of [`TaskManager`]
use super::{TaskControlBlock, TaskStatus, current_task};
use crate::sync::UPSafeCell;
use crate::config::MAX_SYSCALL_NUM;
use crate::mm::{MapPermission, VirtAddr};
use crate::timer::get_time_ms;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;
///A array of `TaskControlBlock` that is thread-safe
pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
}
use crate::task::TaskStatus::Running;
///TaskInfo struct
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in its life cycle
    pub(crate) status: TaskStatus,
    /// The numbers of syscall called by task
    pub(crate) syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    pub(crate) time: usize,
}
/// A simple FIFO scheduler.
impl TaskManager {
    ///Creat an empty TaskManager
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        self.ready_queue.push_back(task);
    }
    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        // self.ready_queue.pop_front()
        if self.ready_queue.is_empty() {
            println!("fetch none");
            return None;
        }
        let mut ret_idx = 0;
        for (idx, item) in self.ready_queue.iter().enumerate() {
            if idx == ret_idx {
                continue;
            }
            let inner = item.inner_exclusive_access();
            let ret_inner = self.ready_queue[ret_idx].inner_exclusive_access();
            if inner.task_stride < ret_inner.task_stride {
                ret_idx = idx;
            }
        }

        self.ready_queue.remove(ret_idx)
    }
    fn get_task_info(&self) -> TaskInfo {
        let task= current_task().unwrap();
        let inner = task.inner_exclusive_access();
        let current_time = get_time_ms();
        TaskInfo{
            status: Running,
            syscall_times:inner.sys_call_times,
            time:current_time,
        }
    }

    fn add_syscall_time(&self, syscall_id: usize) {
        let task= current_task().unwrap();
        let mut inner = task.inner_exclusive_access();
        inner.sys_call_times[syscall_id] +=1;
    }
    fn m_map(&self, start: usize, len: usize, port: usize) -> isize {
        let task= current_task().unwrap();
        let mut inner = task.inner_exclusive_access();
        let memory_set = &mut inner.memory_set;

        let start_va = VirtAddr::from(start);
        let end_va = VirtAddr::from(start + len);
        let permission: MapPermission =
            MapPermission::from_bits((port as u8) << 1).unwrap() | MapPermission::U;

        if memory_set.include_allocated(start_va, end_va) {
            return -1;
        }
        if !start_va.aligned() || (port & !0x7 != 0) || (port & 0x7 == 0) {
            return -1;
        }

        memory_set.insert_framed_area(start_va, end_va, permission);
        0
    }

    fn m_unmap(&self, start: usize, len: usize) -> isize {
        let task= current_task().unwrap();
        let mut inner = task.inner_exclusive_access();
        let memory_set = &mut inner.memory_set;

        let start_va = VirtAddr::from(start);
        let end_va = VirtAddr::from(start + len);

        if !start_va.aligned() || !end_va.aligned() {
            return -1;
        }

        memory_set.free_framed_area(start_va, end_va);
        0
    }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

/// Add process to ready queue
pub fn add_task(task: Arc<TaskControlBlock>) {
    //trace!("kernel: TaskManager::add_task");
    TASK_MANAGER.exclusive_access().add(task);
}

/// Take a process out of the ready queue
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    //trace!("kernel: TaskManager::fetch_task");
    TASK_MANAGER.exclusive_access().fetch()
}
/// Get the current task info
pub fn get_task_info() -> TaskInfo {
    //trace!("kernel: TaskManager::get_task_info");
    TASK_MANAGER.exclusive_access().get_task_info()
}
///Add syscall time
pub fn add_syscall_time(syscall_id: usize) {
    //trace!("kernel: TaskManager::add_syscall_time");
    TASK_MANAGER.exclusive_access().add_syscall_time(syscall_id);
}
/// Map a memory area
pub fn task_mmap(start: usize, len: usize, port: usize) -> isize {
    //trace!("kernel: TaskManager::m_map");
    TASK_MANAGER.exclusive_access().m_map(start, len, port)
}
/// Unmap a memory area
pub fn task_unmap(start: usize, len: usize) -> isize {
    TASK_MANAGER.exclusive_access().m_unmap(start, len)
}