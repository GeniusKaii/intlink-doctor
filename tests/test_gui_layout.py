"""GUI 布局回归：抓取真实窗口画面，检查关键控件的位置关系。

为什么不用「截图看人眼」：锁屏时全屏截图只能拿到锁屏画面，
而且人眼看不出「输入框被说明文字挤窄」这种问题。
这里用 PrintWindow 直接让窗口绘制到内存，再量控件的几何位置。

检查的是排版规则，不是像素比对（像素一改字体就失效）：
  - 主输入框不能比它右边的说明文字还窄
  - 说明文字要紧跟在所属输入框之后，不能被推到窗口最右
  - 三块区域（连接/采集/输出）都要有高度
"""
from __future__ import annotations

import ctypes
import os
import sys
import tkinter as tk
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intlink_doctor import gui as G

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32
PW_RENDERFULLCONTENT = 0x00000002

FAIL = 0


def chk(cond, msg):
    global FAIL
    if cond:
        print("  PASS %s" % msg)
    else:
        print("  FAIL %s" % msg)
        FAIL += 1


def capture(hwnd: int, out_bmp: str) -> bool:
    rect = wintypes.RECT()
    user32.GetClientRect(hwnd, ctypes.byref(rect))
    w, h = rect.right, rect.bottom
    if w <= 0 or h <= 0:
        return False
    hdc = user32.GetDC(hwnd)
    mdc = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    gdi32.SelectObject(mdc, bmp)
    ok = user32.PrintWindow(hwnd, mdc, PW_RENDERFULLCONTENT)

    class BIH(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
                    ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                    ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                    ("biClrImportant", wintypes.DWORD)]
    bi = BIH()
    bi.biSize = ctypes.sizeof(BIH)
    bi.biWidth = w
    bi.biHeight = -h
    bi.biPlanes = 1
    bi.biBitCount = 32
    buf = ctypes.create_string_buffer(w * 4 * h)
    got = gdi32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bi), 0)
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mdc)
    user32.ReleaseDC(hwnd, hdc)
    if not got or not ok:
        return False

    import struct
    data = buf.raw
    hdr = struct.pack("<2sIHHI", b"BM", 14 + 40 + len(data), 0, 0, 54)
    info = struct.pack("<IiiHHIIiiII", 40, w, -h, 1, 32, 0, len(data),
                       2835, 2835, 0, 0)
    with open(out_bmp, "wb") as f:
        f.write(hdr + info + data)
    return True


def find_widgets(root):
    """遍历所有控件，返回 [(类名, 文本, x, y, w, h)]。"""
    out = []

    def walk(w):
        try:
            iw = w.winfo_width()
            ih = w.winfo_height()
            if iw > 1 and ih > 1:
                try:
                    txt = w.cget("text")
                except Exception:
                    txt = ""
                out.append((w.winfo_class(), str(txt), w.winfo_rootx(),
                            w.winfo_rooty(), iw, ih))
        except Exception:
            pass
        for c in w.winfo_children():
            walk(c)

    walk(root)
    return out


def main():
    root = tk.Tk()
    app = G.App(root)
    root.update_idletasks()
    root.update()
    root.lift()
    root.update_idletasks()
    root.update()

    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui-shots")
    os.makedirs(outdir, exist_ok=True)
    bmp = os.path.join(outdir, "gui_layout.bmp")
    png = os.path.join(outdir, "gui_layout.png")

    hwnd = user32.GetParent(root.winfo_id()) or root.winfo_id()
    cap_ok = capture(hwnd, bmp)
    chk(cap_ok, "能抓取窗口画面（PrintWindow，锁屏也可用）")
    if cap_ok:
        try:
            from PIL import Image
            Image.open(bmp).save(png)
            os.remove(bmp)
            print("    画面: %s (%dx%d)" % (png, Image.open(png).size[0],
                                            Image.open(png).size[1]))
        except ImportError:
            print("    没有 Pillow，保留 BMP: %s" % bmp)

    widgets = find_widgets(root)
    print("    控件数: %d" % len(widgets))

    hint_entry = [w for w in widgets if w[0] == "TEntry"]
    chk(len(hint_entry) >= 4, "表单里有足够输入框（%d 个）" % len(hint_entry))

    # 主输入框（程序线索）应该在 y 约 240 的位置且宽度够大
    labels = [w for w in widgets if w[0] == "TLabel" and w[1]]
    prog = [w for w in labels if "程序名/路径/PID" in w[1]]
    chk(bool(prog), "找到「程序线索」的说明文字")
    if prog:
        px, py, pw, ph = prog[0][2], prog[0][3], prog[0][4], prog[0][5]
        # 找同一行、在它左边最近的输入框
        same_row = [e for e in hint_entry
                    if abs(e[3] - py) < 26 and e[2] < px]
        if same_row:
            entry = max(same_row, key=lambda e: e[2])
            chk(entry[4] >= pw * 0.85,
                "程序线索输入框(%dpx) 不窄于说明文字(%dpx)" % (entry[4], pw))
            chk(entry[2] + entry[4] <= px + 12,
                "说明文字紧跟在输入框之后，没有被挤到最右")
        else:
            chk(False, "找不到与说明同一行的输入框")

    # 三块区域都要有高度（连接/采集/输出）
    frames = [w for w in widgets if w[0] == "TLabelframe"]
    chk(len(frames) >= 3, "三大区域都在（%d 个 Labelframe）" % len(frames))
    big = [f for f in frames if f[5] > 120]
    chk(bool(big), "输出区有足够高度（%d 个区域 >120px）" % len(big))

    # 窗口不该有横向滚动条冒出来（说明内容超宽）
    chk(root.winfo_width() >= 900, "窗口宽度合理（%d）" % root.winfo_width())

    root.destroy()
    print("ALL PASS" if FAIL == 0 else "FAILED=%d" % FAIL)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
