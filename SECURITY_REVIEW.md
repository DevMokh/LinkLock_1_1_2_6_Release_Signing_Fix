# LinkLock 1.1.2+5 — سجل الإصلاحات الأمنية

## الإصلاحات المنفذة في هذه النسخة

- حماية نقطة استقبال البلاغات من CSRF: لا تُقبل عمليات POST إلا إذا تطابقت ترويسة `Origin` تمامًا مع أصل Worker الحالي. أضيف اختبار للطلبات ذات Origin المفقود أو القادم من موقع آخر.

- صفحة وسيطة تعرض hostname وتطلب ضغطًا صريحًا على متابعة. روابط المشاركة الجديدة تستخدم `GET /s/{id}.{keyId}.{iv}.{ciphertext}` وتضمّن النص المشفّر داخل المسار، بينما التحويل متاح فقط عبر `POST /go/{token}` من نفس الأصل؛ روابط `/s/{id}` القديمة ما زالت مدعومة.
- إضافة بلاغات إساءة الاستخدام لأسباب محددة (`phishing`, `malware`, `spam`, `other`) مع Rate Limit مستقل، وحد 1 KiB للطلب، وتخزين معرّف المشاركة والسبب والوقت فقط. لا يدّعي النظام أن البلاغ يحظر المشاركة تلقائيًا.
- رفض محارف Unicode من الفئة `Cf` ومحارف التحكم `Cc` في Dart وWorker، بما يشمل U+2060 وU+200B وعلامات اتجاه النص.
- إضافة `key_id` إلى سجلات D1 وkey ring عبر `LINKLOCK_MASTER_KEYS` و`LINKLOCK_ACTIVE_KEY_ID`. يحتفظ المشغّل بمفاتيح الإصدارات القديمة لفتح المشاركات القائمة. الترحيل `0002_key_rotation_and_reports.sql` يضيف العمود وجدول البلاغات.
- تعطيل Android backup وdevice transfer للتطبيق باستخدام `allowBackup=false` وقواعد استخراج تستبعد بيانات التطبيق.
- إضافة مصادقة محلية عند تشغيل التطبيق والعودة من الخلفية باستخدام البصمة أو PIN/نمط/كلمة مرور قفل الجهاز، عندما يدعمها نظام الجهاز. لا يفرض التطبيق قفلًا على جهاز لا يوفّر مصادقة محلية مدعومة.
- منع توقيع Release بمفتاح Debug؛ يتطلب بناء Release keystore خاصًا ومتغيرات بيئة منفصلة.
- حفظ سجل حتى 100 مشاركة ورموز إلغائها في `flutter_secure_storage`، مع ترحيل سجل المشاركة الوحيد من الإصدارات السابقة.
- تصحيح وصف الحزمة: AES-128-GCM في وضع المشاركة لأن المفتاح مضمن في النص، وAES-256-GCM في وضع الجهاز، وAES-256-GCM منفصل على الخادم.

## اختبارات تم تنفيذها في بيئة التحرير

| الفحص | النتيجة |
|---|---:|
| `node --check server/src/index.js` | ناجح |
| `npm test` داخل `server/` | 17/17 ناجح |
| اختبار تضمين Ciphertext داخل رابط المشاركة ورفض التلاعب به | ناجح |
| اختبار توافق روابط ID القديمة | ناجح |
| اختبار صفحة التحذير وعدم التحويل التلقائي | ناجح |
| اختبار التحويل فقط عبر `/go/{token}` | ناجح |
| رفض محارف Unicode المخفية ومحارف التحكم في Worker | ناجح |
| تدوير المفتاح مع استمرار فتح سجلات v1 وv2 | ناجح |
| اختبار البلاغات وحدّ الطلب | ناجح |
| تحليل Android Manifest وData Extraction XML | ناجح |
| Flutter/Dart format/analyze/test | لم تُشغّل؛ Flutter/Dart غير متاحين في بيئة التحرير |
| بناء APK | لم يُنفّذ |
| اختبار مصادقة البصمة/PIN على جهاز Android فعلي | لم يُنفّذ |
| تطبيق ترحيلات D1 على حساب Cloudflare حقيقي | لم يُنفّذ |
| نشر Worker على Cloudflare | لم يُنفّذ |

## قيود متبقية قبل النشر العام

1. صفحة التحذير وميزة الإبلاغ لا تكفيان وحدهما لمنع التصيّد. البلاغات لا تحظر الروابط تلقائيًا؛ يلزم إجراء مراجعة أو قائمة حظر إدارية ومراقبة تشغيلية. يستطيع مالك الخادم مراجعة آخر البلاغات باستعلام D1 الموثّق في README.
2. مشاركة الويب ليست تشفيرًا طرفيًا. Worker قادر على فك تشفير الوجهة؛ وعنوان الوجهة يظهر في المتصفح بعد المتابعة.
3. كود الاسترجاع هو تمثيل للمفتاح العشوائي الكامل، وليس كلمة مرور مستقلة. من يمتلكه يستطيع فتح الروابط المحمية بمفتاح الجهاز.
4. مصادقة التطبيق تعتمد على قفل الجهاز. إذا لم يوفّر الجهاز مصادقة محلية مدعومة، لا يفرض التطبيق قفلًا.
5. لا يُعتمد Release قبل توفير keystore خاص وتشغيل GitHub Actions بنجاح، بما يشمل `flutter analyze` و`flutter test` والبناء.
6. يجب استبدال D1 `database_id` وتعيين `namespace_id` فريد لكل Rate Limit binding في حساب Cloudflare قبل النشر.


## 1.1.2+5 — same-origin abuse reports

- The abuse-report form now requires an exact same-origin `Origin` header. Cross-origin and Origin-less report submissions are rejected.

## 1.1.2+4 — encrypted payload embedded in share URL

- New share URLs contain the share ID, master-key version ID, AES-GCM IV, and ciphertext in the path. The master key is never embedded in the URL.
- The Worker compares the path payload with the D1 record before decrypting, and keeps expiration/revocation checks in D1.
- Old ID-only links remain supported for compatibility.
- The destination hostname is shown before confirmation; after confirmation the browser navigates to the original HTTP(S) URL normally.
- This remains server-side encryption, not end-to-end encryption: Cloudflare Worker can decrypt the destination. Anyone holding the share URL can use it until expiry or revocation.
