"""MNIST CNN 학습 → model/mnist.keras 저장.

학습 데이터는 Keras 가 제공하는 mnist.npz 를 사용하며, keras.datasets.mnist.load_data 는
내려받은 파일의 SHA-256 을 검증한다. 저장 형식은 pickle 이 없는 Keras v3(.keras) 이다.
학습 후 `trustchain aibom` 으로 AI-BOM 을 생성해 가중치 해시를 기록한다.
"""

from pathlib import Path

import keras
import numpy as np

OUT = Path(__file__).resolve().parent / "model" / "mnist.keras"


def main(epochs: int = 3) -> None:
    keras.utils.set_random_seed(42)
    (x_train, y_train), (x_test, y_test) = keras.datasets.mnist.load_data()
    x_train = (x_train.astype("float32") / 255.0)[..., np.newaxis]
    x_test = (x_test.astype("float32") / 255.0)[..., np.newaxis]
    model = keras.Sequential([
        keras.Input(shape=(28, 28, 1)),
        keras.layers.Conv2D(32, 3, activation="relu"),
        keras.layers.MaxPooling2D(),
        keras.layers.Conv2D(64, 3, activation="relu"),
        keras.layers.MaxPooling2D(),
        keras.layers.Flatten(),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(10, activation="softmax"),
    ])
    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    model.fit(x_train, y_train, epochs=epochs, batch_size=128, validation_split=0.1, verbose=2)
    _, acc = model.evaluate(x_test, y_test, verbose=0)
    print(f"test accuracy: {acc:.4f}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    model.save(OUT)
    print(f"saved: {OUT}")


if __name__ == "__main__":
    main()
