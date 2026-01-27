import os
import shutil
import random

print("🚀 Script started")

SOURCE = r"dataset\data\train"
TARGET = r"dataset\data\val"
SPLIT = 0.2

classes = ["organic", "recyclable"]

for cls in classes:
    cls_path = os.path.join(SOURCE, cls)
    imgs = os.listdir(cls_path)
    random.shuffle(imgs)

    n = int(len(imgs) * SPLIT)
    print(f"\n➡ {cls.upper()} | Total: {len(imgs)} | Moving: {n}")

    for i, img in enumerate(imgs[:n], start=1):
        src = os.path.join(cls_path, img)
        dst = os.path.join(TARGET, cls, img)
        shutil.copy(src, dst)

        if i % 100 == 0:
            print(f"   Copied {i}/{n}")

print("\n✅ DONE — validation set created")
