from flask import Flask, request, render_template
import joblib
import os
from phishing_detector4 import analyze_url, extract_features_for_model

# تحديد مسار مجلد القوالب بشكل صحيح
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../frontend")

app = Flask(__name__, template_folder=template_dir)  # هنا نمرر المسار

# تحميل النموذج و LabelEncoder مرة واحدة عند بدء التطبيق
model = joblib.load('model.pkl')
le = joblib.load('label_encoder.pkl')

@app.route('/', methods=['GET', 'POST'])
def dashboard():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            report = analyze_url(url)
            try:
                features_df = extract_features_for_model(report["normalized_url"])
                pred_num = model.predict(features_df)[0]
                pred_label = le.inverse_transform([pred_num])[0]
                report["ml_prediction"] = pred_label  # عرض التسمية بدل الرقم
                report["ml_label"] = pred_label
            except Exception as e:
                report["notes"].append(f"Prediction failed: {str(e)}")
                report["ml_prediction"] = None
                report["ml_label"] = None
            result = report

    return render_template('dashboard4.html', result=result)

if __name__ == "__main__":
    app.run(debug=True)
