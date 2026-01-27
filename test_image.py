from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
import numpy as np

model = load_model("waste_model.h5")

# 👇 get image size directly from model
img_height, img_width = model.input_shape[1], model.input_shape[2]
print("Using image size:", img_height, img_width)

img = image.load_img("test.jpg", target_size=(img_height, img_width))
img_array = image.img_to_array(img)
img_array = img_array / 255.0
img_array = np.expand_dims(img_array, axis=0)

prediction = model.predict(img_array)[0][0]

if prediction > 0.5:
    print(f"♻️ Recyclable Waste ({prediction:.2f})")
else:
    print(f"🍃 Organic Waste ({1-prediction:.2f})")
