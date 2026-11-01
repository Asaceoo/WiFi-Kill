"""生成托盘与程序图标。

关键点：**按尺寸分别绘制**，而不是画一张大的再缩小。
16px 下如果沿用大图的笔画宽度与元素数量，缩完就是一团糊；
小尺寸必须走「少元素 + 粗笔画」。
"""

from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]

# 莫兰迪深绿底 + 米白信号 + 灰玫瑰斜杠
BG_TOP = (110, 132, 119)
BG_BOT = (78, 97, 86)
INK = (247, 245, 240)
SLASH = (214, 146, 134)


def _bg(size: int) -> Image.Image:
    """圆角底板 + 竖向双色渐变。"""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    pad = max(1, round(size * 0.045))
    radius = max(2, round(size * 0.235))

    grad = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grad)
    for y in range(size):
        t = y / max(1, size - 1)
        c = tuple(round(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * t) for i in range(3))
        gd.line([(0, y), (size, y)], fill=c + (255,))

    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [pad, pad, size - pad - 1, size - pad - 1], radius=radius, fill=255)
    img.paste(grad, (0, 0), mask)
    return img


def draw_icon(size: int) -> Image.Image:
    img = _bg(size)
    d = ImageDraw.Draw(img)

    # 按尺寸决定元素数量：16px 只放一道弧，多一道就糊
    if size <= 20:
        radii = (size * 0.30,)
        width = max(2, round(size * 0.135))
        lw = size * 0.115
    elif size <= 32:
        radii = (size * 0.325, size * 0.20)
        width = max(2, round(size * 0.115))
        lw = size * 0.105
    else:
        radii = (size * 0.335, size * 0.215, size * 0.098)
        width = max(3, round(size * 0.082))
        lw = size * 0.088

    cx, cy = size * 0.50, size * 0.665
    for r in radii:
        d.arc([cx - r, cy - r, cx + r, cy + r], start=203, end=337,
              fill=INK + (255,), width=width)

    if size > 24:                       # 太小的尺寸上圆点会被斜杠吃掉
        dot = max(1.5, size * 0.052)
        d.ellipse([cx - dot, cy - dot, cx + dot, cy + dot], fill=INK + (255,))

    # 斜杠：先铺一层底色描边再画本体，避免和弧线糊在一起
    lw = max(2.0, lw)
    p0 = (size * 0.255, size * 0.215)
    p1 = (size * 0.745, size * 0.815)
    for w, col in ((lw * 1.6, BG_BOT + (255,)), (lw, SLASH + (255,))):
        d.line([p0, p1], fill=col, width=round(w))
        r = w / 2
        for x, y in (p0, p1):
            d.ellipse([x - r, y - r, x + r, y + r], fill=col)
    return img


def main():
    frames = [draw_icon(s) for s in SIZES]
    frames[-1].save(OUT / "wifikill.ico", format="ICO",
                    sizes=[(s, s) for s in SIZES])
    draw_icon(256).save(OUT / "wifikill.png")

    # 预览：把 16 / 24 / 32 放大到 128，用最近邻看真实像素
    preview = Image.new("RGBA", (128 * 3 + 40, 160), (242, 240, 236, 255))
    for i, s in enumerate((16, 24, 32)):
        im = draw_icon(s).resize((128, 128), Image.NEAREST)
        preview.paste(im, (10 + i * 138, 16), im)
    preview.save(OUT / "docs" / "images" / "icon_preview.png")
    print("icon ok:", ", ".join(f"{s}px" for s in SIZES))


if __name__ == "__main__":
    main()
