import sys
import json
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing import image
import os

# 🔇 Silence TensorFlow logs COMPLETELY
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
tf.get_logger().setLevel('ERROR')

MODEL_PATH = "waste_model.h5"
IMG_SIZE = 128

# Load model once
model = tf.keras.models.load_model(MODEL_PATH)

# Validate argument
if len(sys.argv) < 2:
    print(json.dumps({ "error": "No image path provided" }))
    sys.exit(1)

img_path = sys.argv[1]

# Load & preprocess image
img = image.load_img(img_path, target_size=(IMG_SIZE, IMG_SIZE))
img_array = image.img_to_array(img) / 255.0
img_array = np.expand_dims(img_array, axis=0)

# Predict
prediction = model.predict(img_array, verbose=0)[0][0]

if prediction > 0.5:
    result = {
        "label": "Recyclable",
        "confidence": float(prediction)
    }
else:
    result = {
        "label": "Organic",
        "confidence": float(1 - prediction)
    }

# ✅ ONLY JSON OUTPUT
print(json.dumps(result))
