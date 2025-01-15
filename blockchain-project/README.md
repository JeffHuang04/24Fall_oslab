# OSLab

week1~week12 [链接](https://git.nju.edu.cn/os-lab/operating-system-design-and-implementation)

实验讲义与注意事项：左侧栏选择[Wiki](https://git.nju.edu.cn/os-lab/blockchain-project/-/wikis/home)

注：OJ平台请尽量用校内网连接，使用VPN可能无法访问。

## 使用docker配置开发环境

你可以借助我们提供的Dockerfile快速配置开发环境。

只需在命令行启动脚本（记得增加可执行权限）：

```bash
./start.sh
```

第一次启动会拉取并配置docker image，需要的时间比较长，之后就很快了.

如果你没有办法拉取ubuntu:22.04基础镜像，你可以在国内镜像源手动拉取（注意使用linux/amd64架构）.

你可以在路径下多次运行启动脚本，进入到同一个容器里，开启多个程序测试进程间通信（不过当你的第一个终端退出容器，其他终端也相应退出了）。

注意：你可以在容器中执行开发+本地评测，但是没有办法提交到online-judge！