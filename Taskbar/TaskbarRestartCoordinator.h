#ifndef TASKBARRESTARTCOORDINATOR_H
#define TASKBARRESTARTCOORDINATOR_H

namespace TaskbarRestartCoordinator
{
    // scheduleAfterCurrentProcessExit：启动携带当前 PID 的同程序接替实例。
    // 接替实例会在正常初始化前等待当前进程真正退出；返回是否成功启动接替实例。
    bool scheduleAfterCurrentProcessExit();

    // waitForPredecessorIfRequested：处理 --restart-after-pid 启动参数。
    // 未携带参数时直接返回 true；携带时等待旧进程退出，参数或等待失败返回 false。
    bool waitForPredecessorIfRequested();
}

#endif
