#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NCM to MP3 Converter
网易云音乐NCM格式转MP3工具
"""

import os
import sys
import json
import struct
import base64
import binascii
import threading
from pathlib import Path

from Crypto.Cipher import AES
from mutagen.mp3 import MP3
from mutagen.id3 import ID3, APIC, TIT2, TPE1, TALB

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QFileDialog, QListWidget,
    QListWidgetItem, QMessageBox, QProgressBar, QComboBox,
    QGroupBox, QSplitter, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QMimeData
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QIcon, QFont


class NCMDecryptor:
    """NCM文件解密器"""
    
    # NCM文件魔数
    MAGIC_HEADER = b'CTENFDAM'
    
    # 核心密钥 (用于解密音频数据密钥)
    CORE_KEY = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    
    # 元数据密钥 (用于解密歌曲信息)
    META_KEY = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    
    @staticmethod
    def unpad(data):
        """去除PKCS7填充"""
        pad_len = data[-1] if isinstance(data[-1], int) else ord(data[-1])
        return data[:-pad_len]
    
    @classmethod
    def decrypt_file(cls, input_path, output_dir=None):
        """
        解密单个NCM文件
        
        Args:
            input_path: NCM文件路径
            output_dir: 输出目录，None则使用原文件所在目录
            
        Returns:
            dict: 包含输出路径、元数据、成功状态的信息
        """
        try:
            input_path = Path(input_path)
            
            if not input_path.exists():
                return {'success': False, 'error': f'文件不存在: {input_path}'}
            
            if output_dir:
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
            else:
                output_dir = input_path.parent
            
            with open(input_path, 'rb') as f:
                # 读取并验证文件头
                header = f.read(8)
                if header != cls.MAGIC_HEADER:
                    return {'success': False, 'error': '不是有效的NCM文件'}
                
                # 跳过2字节未知数据
                f.seek(2, 1)
                
                # 读取密钥长度和密钥数据
                key_length = struct.unpack('<I', f.read(4))[0]
                key_data = bytearray(f.read(key_length))
                
                # 密钥数据异或0x64
                for i in range(len(key_data)):
                    key_data[i] ^= 0x64
                
                # AES-ECB解密密钥
                cryptor = AES.new(cls.CORE_KEY, AES.MODE_ECB)
                key_data = cls.unpad(cryptor.decrypt(bytes(key_data)))[17:]
                
                # 构建密钥盒 (RC4-like)
                key_length = len(key_data)
                key_data = bytearray(key_data)
                key_box = bytearray(range(256))
                
                c = 0
                last_byte = 0
                key_offset = 0
                
                for i in range(256):
                    swap = key_box[i]
                    c = (swap + last_byte + key_data[key_offset]) & 0xff
                    key_offset += 1
                    if key_offset >= key_length:
                        key_offset = 0
                    key_box[i] = key_box[c]
                    key_box[c] = swap
                    last_byte = c
                
                # 读取元数据
                meta_length = struct.unpack('<I', f.read(4))[0]
                meta_data = bytearray(f.read(meta_length))
                
                # 元数据异或0x63
                for i in range(len(meta_data)):
                    meta_data[i] ^= 0x63
                
                # Base64解码并AES解密元数据
                meta_data = bytes(meta_data)
                meta_data = base64.b64decode(meta_data[22:])
                cryptor = AES.new(cls.META_KEY, AES.MODE_ECB)
                meta_data = cls.unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
                meta_data = json.loads(meta_data)
                
                # 读取CRC32校验码
                crc32 = struct.unpack('<I', f.read(4))[0]
                
                # 跳过5字节
                f.seek(5, 1)
                
                # 读取封面图片
                image_size = struct.unpack('<I', f.read(4))[0]
                image_data = f.read(image_size) if image_size > 0 else None
                
                # 确定输出格式和文件名（强制转换为mp3）
                music_name = meta_data.get('musicName', input_path.stem)
                music_format = 'mp3'  # 强制输出为mp3格式
                
                # 清理文件名中的非法字符
                safe_name = "".join(c for c in music_name if c not in '<>:"/\\|?*')
                if not safe_name:
                    safe_name = input_path.stem
                
                output_path = output_dir / f"{safe_name}.{music_format}"
                
                # 如果文件已存在，添加序号
                counter = 1
                original_output = output_path
                while output_path.exists():
                    output_path = output_dir / f"{safe_name}_{counter}.{music_format}"
                    counter += 1
                
                # 解密音频数据并写入文件
                with open(output_path, 'wb') as out_file:
                    while True:
                        chunk = bytearray(f.read(0x8000))
                        chunk_length = len(chunk)
                        
                        if not chunk:
                            break
                        
                        # RC4解密
                        for i in range(1, chunk_length + 1):
                            j = i & 0xff
                            chunk[i - 1] ^= key_box[
                                (key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff
                            ]
                        
                        out_file.write(chunk)
                
                # 写入封面和元数据到MP3
                if music_format.lower() == 'mp3' and image_data:
                    try:
                        cls._write_mp3_tags(output_path, meta_data, image_data)
                    except Exception as e:
                        print(f"写入MP3标签失败: {e}")
                
                return {
                    'success': True,
                    'output_path': str(output_path),
                    'metadata': meta_data,
                    'format': music_format
                }
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @classmethod
    def _write_mp3_tags(cls, file_path, meta_data, image_data):
        """写入MP3标签信息"""
        try:
            audio = MP3(file_path)
            
            if audio.tags is None:
                audio.add_tags()
            
            # 写入标题
            if 'musicName' in meta_data:
                audio.tags['TIT2'] = TIT2(encoding=3, text=meta_data['musicName'])
            
            # 写入艺术家
            if 'artist' in meta_data and meta_data['artist']:
                artists = []
                for artist in meta_data['artist']:
                    if isinstance(artist, list) and len(artist) > 0:
                        artists.append(artist[0])
                    elif isinstance(artist, str):
                        artists.append(artist)
                if artists:
                    audio.tags['TPE1'] = TPE1(encoding=3, text=artists)
            
            # 写入专辑
            if 'album' in meta_data:
                audio.tags['TALB'] = TALB(encoding=3, text=meta_data['album'])
            
            # 写入封面
            if image_data:
                # 检测图片格式
                mime = 'image/jpeg'
                if image_data[:8] == b'\x89PNG\r\n\x1a\n':
                    mime = 'image/png'
                
                audio.tags['APIC'] = APIC(
                    encoding=3,
                    mime=mime,
                    type=3,
                    desc='Cover',
                    data=image_data
                )
            
            audio.save()
            
        except Exception as e:
            print(f"写入标签错误: {e}")


class ConvertWorker(QThread):
    """转换工作线程"""
    
    progress_signal = pyqtSignal(int, int)  # 当前进度, 总数
    file_complete_signal = pyqtSignal(str, bool, str)  # 文件名, 是否成功, 消息
    all_complete_signal = pyqtSignal(int, int)  # 成功数, 失败数
    
    def __init__(self, files, output_dir):
        super().__init__()
        self.files = files
        self.output_dir = output_dir
        self.is_running = True
    
    def run(self):
        total = len(self.files)
        success_count = 0
        fail_count = 0
        
        for i, file_path in enumerate(self.files):
            if not self.is_running:
                break
            
            self.progress_signal.emit(i + 1, total)
            
            result = NCMDecryptor.decrypt_file(file_path, self.output_dir)
            
            file_name = os.path.basename(file_path)
            
            if result['success']:
                success_count += 1
                self.file_complete_signal.emit(
                    file_name, True, f"已保存: {result['output_path']}"
                )
            else:
                fail_count += 1
                self.file_complete_signal.emit(
                    file_name, False, f"失败: {result['error']}"
                )
        
        self.all_complete_signal.emit(success_count, fail_count)
    
    def stop(self):
        self.is_running = False


class DropArea(QFrame):
    """拖拽区域"""
    
    files_dropped = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setMinimumHeight(150)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.label = QLabel("拖拽NCM文件到此处\n或点击「添加文件」按钮")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("""
            QLabel {
                color: #666;
                font-size: 14px;
                padding: 20px;
            }
        """)
        layout.addWidget(self.label)
        
        self.setStyleSheet("""
            DropArea {
                background-color: #f8f9fa;
                border: 2px dashed #adb5bd;
                border-radius: 10px;
            }
            DropArea:hover {
                border-color: #495057;
                background-color: #e9ecef;
            }
        """)
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet("""
                DropArea {
                    background-color: #e7f3ff;
                    border: 2px dashed #0066cc;
                    border-radius: 10px;
                }
            """)
    
    def dragLeaveEvent(self, event):
        self.setStyleSheet("""
            DropArea {
                background-color: #f8f9fa;
                border: 2px dashed #adb5bd;
                border-radius: 10px;
            }
        """)
    
    def dropEvent(self, event: QDropEvent):
        self.setStyleSheet("""
            DropArea {
                background-color: #f8f9fa;
                border: 2px dashed #adb5bd;
                border-radius: 10px;
            }
        """)
        
        files = []
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if os.path.isfile(file_path) and file_path.lower().endswith('.ncm'):
                files.append(file_path)
            elif os.path.isdir(file_path):
                for root, dirs, filenames in os.walk(file_path):
                    for filename in filenames:
                        if filename.lower().endswith('.ncm'):
                            files.append(os.path.join(root, filename))
        
        if files:
            self.files_dropped.emit(files)


class MainWindow(QMainWindow):
    """主窗口"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NCM转MP3转换器")
        self.setMinimumSize(800, 600)
        
        self.files_to_convert = []
        self.worker = None
        
        self.init_ui()
    
    def init_ui(self):
        # 中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # 标题
        title_label = QLabel("网易云音乐 NCM 转 MP3 转换器")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: bold;
                color: #2c3e50;
                padding: 10px;
            }
        """)
        main_layout.addWidget(title_label)
        
        # 拖拽区域
        self.drop_area = DropArea()
        self.drop_area.files_dropped.connect(self.add_files)
        main_layout.addWidget(self.drop_area)
        
        # 文件列表区域
        list_group = QGroupBox("待转换文件列表")
        list_layout = QVBoxLayout(list_group)
        
        # 文件列表
        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        list_layout.addWidget(self.file_list)
        
        # 列表按钮
        btn_layout = QHBoxLayout()
        
        self.add_btn = QPushButton("添加文件")
        self.add_btn.setStyleSheet(self._get_button_style("#28a745"))
        self.add_btn.clicked.connect(self.browse_files)
        btn_layout.addWidget(self.add_btn)
        
        self.add_folder_btn = QPushButton("添加文件夹")
        self.add_folder_btn.setStyleSheet(self._get_button_style("#17a2b8"))
        self.add_folder_btn.clicked.connect(self.browse_folder)
        btn_layout.addWidget(self.add_folder_btn)
        
        self.remove_btn = QPushButton("移除选中")
        self.remove_btn.setStyleSheet(self._get_button_style("#ffc107", "#000"))
        self.remove_btn.clicked.connect(self.remove_selected)
        btn_layout.addWidget(self.remove_btn)
        
        self.clear_btn = QPushButton("清空列表")
        self.clear_btn.setStyleSheet(self._get_button_style("#dc3545"))
        self.clear_btn.clicked.connect(self.clear_files)
        btn_layout.addWidget(self.clear_btn)
        
        list_layout.addLayout(btn_layout)
        main_layout.addWidget(list_group)
        
        # 输出设置
        output_group = QGroupBox("输出设置")
        output_layout = QHBoxLayout(output_group)
        
        output_layout.addWidget(QLabel("保存位置:"))
        
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("默认保存到原文件所在目录")
        output_layout.addWidget(self.output_edit)
        
        self.browse_output_btn = QPushButton("浏览...")
        self.browse_output_btn.setStyleSheet(self._get_button_style("#6c757d"))
        self.browse_output_btn.clicked.connect(self.browse_output_dir)
        output_layout.addWidget(self.browse_output_btn)
        
        main_layout.addWidget(output_group)
        
        # 进度区域
        progress_group = QGroupBox("转换进度")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("就绪")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_layout.addWidget(self.status_label)
        
        main_layout.addWidget(progress_group)
        
        # 转换按钮
        self.convert_btn = QPushButton("开始转换")
        self.convert_btn.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 15px;
                font-size: 16px;
                font-weight: bold;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QPushButton:disabled {
                background-color: #6c757d;
            }
        """)
        self.convert_btn.clicked.connect(self.start_conversion)
        main_layout.addWidget(self.convert_btn)
        
        # 状态栏
        self.statusBar().showMessage("就绪")
    
    def _get_button_style(self, bg_color, text_color="white"):
        return f"""
            QPushButton {{
                background-color: {bg_color};
                color: {text_color};
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {bg_color}dd;
            }}
        """
    
    def add_files(self, files):
        """添加文件到列表"""
        added = 0
        for file_path in files:
            if file_path not in self.files_to_convert:
                self.files_to_convert.append(file_path)
                item = QListWidgetItem(os.path.basename(file_path))
                item.setToolTip(file_path)
                self.file_list.addItem(item)
                added += 1
        
        self.statusBar().showMessage(f"已添加 {len(self.files_to_convert)} 个文件")
    
    def browse_files(self):
        """浏览文件"""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "选择NCM文件",
            "",
            "网易云音乐文件 (*.ncm);;所有文件 (*.*)"
        )
        if files:
            self.add_files(files)
    
    def browse_folder(self):
        """浏览文件夹"""
        folder = QFileDialog.getExistingDirectory(self, "选择包含NCM文件的文件夹")
        if folder:
            files = []
            for root, dirs, filenames in os.walk(folder):
                for filename in filenames:
                    if filename.lower().endswith('.ncm'):
                        files.append(os.path.join(root, filename))
            if files:
                self.add_files(files)
            else:
                QMessageBox.information(self, "提示", "所选文件夹中没有找到NCM文件")
    
    def remove_selected(self):
        """移除选中的文件"""
        selected_items = self.file_list.selectedItems()
        for item in selected_items:
            index = self.file_list.row(item)
            self.file_list.takeItem(index)
            del self.files_to_convert[index]
        
        self.statusBar().showMessage(f"已添加 {len(self.files_to_convert)} 个文件")
    
    def clear_files(self):
        """清空文件列表"""
        self.files_to_convert.clear()
        self.file_list.clear()
        self.statusBar().showMessage("列表已清空")
    
    def browse_output_dir(self):
        """浏览输出目录"""
        folder = QFileDialog.getExistingDirectory(self, "选择保存位置")
        if folder:
            self.output_edit.setText(folder)
    
    def start_conversion(self):
        """开始转换"""
        if not self.files_to_convert:
            QMessageBox.warning(self, "警告", "请先添加要转换的NCM文件")
            return
        
        output_dir = self.output_edit.text() or None
        
        # 禁用按钮
        self.convert_btn.setEnabled(False)
        self.convert_btn.setText("转换中...")
        
        # 创建并启动工作线程
        self.worker = ConvertWorker(self.files_to_convert, output_dir)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.file_complete_signal.connect(self.file_complete)
        self.worker.all_complete_signal.connect(self.all_complete)
        self.worker.start()
    
    def update_progress(self, current, total):
        """更新进度"""
        percentage = int((current / total) * 100)
        self.progress_bar.setValue(percentage)
        self.status_label.setText(f"正在转换: {current}/{total}")
        self.statusBar().showMessage(f"正在转换: {current}/{total}")
    
    def file_complete(self, file_name, success, message):
        """单个文件完成"""
        # 更新列表项显示
        for i in range(self.file_list.count()):
            item = self.file_list.item(i)
            if item.text() == file_name:
                if success:
                    item.setText(f"✓ {file_name}")
                    item.setForeground(Qt.GlobalColor.darkGreen)
                else:
                    item.setText(f"✗ {file_name}")
                    item.setForeground(Qt.GlobalColor.red)
                item.setToolTip(message)
                break
    
    def all_complete(self, success_count, fail_count):
        """全部完成"""
        self.progress_bar.setValue(100)
        
        if fail_count == 0:
            self.status_label.setText(f"转换完成! 成功: {success_count} 个文件")
            QMessageBox.information(
                self,
                "完成",
                f"所有文件转换成功!\n共转换 {success_count} 个文件"
            )
        else:
            self.status_label.setText(
                f"转换完成! 成功: {success_count}, 失败: {fail_count}"
            )
            QMessageBox.warning(
                self,
                "完成",
                f"转换完成!\n成功: {success_count} 个\n失败: {fail_count} 个\n\n"
                f"请检查失败的文件是否有效"
            )
        
        # 恢复按钮
        self.convert_btn.setEnabled(True)
        self.convert_btn.setText("开始转换")
        self.statusBar().showMessage("就绪")


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # 设置应用样式
    app.setStyleSheet("""
        QMainWindow {
            background-color: #f5f5f5;
        }
        QGroupBox {
            font-weight: bold;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
        }
        QListWidget {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 5px;
        }
        QListWidget::item {
            padding: 5px;
            border-bottom: 1px solid #eee;
        }
        QProgressBar {
            border: 1px solid #ddd;
            border-radius: 5px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #007bff;
            border-radius: 5px;
        }
        QLineEdit {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 5px;
        }
    """)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
