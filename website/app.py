from flask import Flask, render_template
from flask import request
import numpy as np
from features import extract_features, encode_features
import pickle
app = Flask(__name__)

@app.route("/", methods=["GET"])
def helloWorld():
    return render_template("index.html")


@app.route("/predict", methods=["POST","GET"])
def Predict():
    url = request.form.get("url")
    score = get_prediction(url)
    if score==1:
        predict = False
    else:
        predict = True
    if predict:
        return render_template("danger.html")
    else:
        return render_template("legit.html")



def get_prediction(url):
    features = extract_features(url)
    print(features)
    voting = pickle.load(open('Trained_Models/model.pkl', 'rb'))
    features = encode_features(features)
    one_hot_enc = pickle.load(open('Trained_Models/One_Hot_Encoder', 'rb'))
    transformed_point = one_hot_enc.transform(np.array(features).reshape(1, -1))
    pred = voting.predict(transformed_point)
    return pred[0]



if __name__=="__main__":
    app.run(debug = True)