# NCM转MP3转换器

一个简单易用的网易云音乐NCM格式转MP3工具，带有图形界面，适合新手使用。

## 功能特点

- 图形界面操作，无需命令行
- 支持拖拽文件和文件夹
- 支持批量转换
- 可自定义保存位置
- 自动保留歌曲元数据（标题、艺术家、专辑、封面）
- 单文件可执行程序，无需安装Python

## 使用方法

### 方法一：直接运行可执行文件（推荐）

1. 下载 `NCM转MP3转换器.exe`
2. 双击运行
3. 拖拽NCM文件到窗口，或点击「添加文件」按钮
4. 选择保存位置（可选，默认保存到原文件目录）
5. 点击「开始转换」

### 方法二：运行Python源码

```bash
pip install -r requirements.txt
python ncm_converter.py
```

## 文件说明

- `ncm_converter.py` - 主程序源码
- `NCM转MP3转换器.exe` - Windows可执行文件
- `requirements.txt` - Python依赖

## 技术原理

- NCM文件使用AES-128加密
- 通过分析文件结构提取密钥
- 使用RC4-like算法解密音频数据
- 使用mutagen库写入MP3标签

## 依赖

- PyQt6 - GUI框架
- pycryptodome - AES解密
- mutagen - MP3标签处理

## 免责声明

本工具仅供个人学习研究使用，请尊重音乐版权，支持正版音乐。
