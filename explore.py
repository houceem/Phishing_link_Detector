import pandas as pd

# مسار ملف البيانات داخل مجلد data
data_path = "data/dataset_phishing.csv"

# قراءة الملف
df = pd.read_csv(data_path)

# عرض أول 5 صفوف
print(df.head())

# معلومات عن الأعمدة والأنواع
print(df.info())

# بعض الإحصائيات الوصفية
print(df.describe())
