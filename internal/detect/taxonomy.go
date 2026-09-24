// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package detect

// DataType describes one kind of personal data.
type DataType struct {
	ID    string `json:"id" yaml:"id"`
	Label string `json:"label" yaml:"label"`
	// Category groups types for the data map: contact, identity, financial,
	// location, device, demographic, health, biometric, online.
	Category string `json:"category" yaml:"category"`
	// Sensitive marks special-category data (GDPR art. 9 and Vietnam's
	// Decree 13/2023/ND-CP "sensitive personal data": health, biometrics,
	// location, financial/bank data, ethnicity, religion...).
	Sensitive bool `json:"sensitive" yaml:"sensitive"`
	// Patterns are space-separated token sequences matched against
	// tokenized identifiers.
	Patterns []string `json:"patterns,omitempty" yaml:"patterns"`
	// Weak patterns are ambiguous abbreviations; matches score lower.
	Weak []string `json:"weak,omitempty" yaml:"weak"`
	// Exclude lists tokens that, when present anywhere in the identifier,
	// mean this is not the data type (e.g. "remote" in remoteAddress).
	Exclude []string `json:"exclude,omitempty" yaml:"exclude"`
}

// DefaultTaxonomy returns a copy of the built-in data types. English and
// Vietnamese names are listed side by side; Vietnamese entries are written
// without diacritics because identifiers are folded before matching.
func DefaultTaxonomy() []DataType {
	out := make([]DataType, len(builtinTaxonomy))
	copy(out, builtinTaxonomy)
	return out
}

var builtinTaxonomy = []DataType{
	{ID: "email", Label: "Email address", Category: "contact",
		Patterns: []string{"email", "e mail", "email address", "email addr", "mail address", "thu dien tu", "dia chi email"},
		Weak:     []string{"mail"},
		Exclude:  []string{"server", "host", "smtp", "port", "provider", "domain"}},
	{ID: "phone", Label: "Phone number", Category: "contact",
		Patterns: []string{"phone", "phone number", "phone no", "phonenumber", "mobile", "mobile number", "mobile no", "msisdn",
			"telephone", "cellphone", "cell phone", "so dien thoai", "sodienthoai", "dien thoai", "dienthoai", "sdt", "so dt", "sodt", "di dong", "didong"},
		Weak:    []string{"tel"},
		Exclude: []string{"app", "os", "platform", "frame", "layout", "screen", "device", "sdk", "version", "notch", "portrait", "landscape", "web", "tablet"}},
	{ID: "person_name", Label: "Person name", Category: "identity",
		Patterns: []string{"full name", "fullname", "first name", "firstname", "last name", "lastname", "given name", "family name",
			"surname", "middle name", "legal name", "ho ten", "hoten", "ho va ten", "hovaten", "ten day du", "ten khach hang",
			"ten nguoi dung", "ten nhan vien", "ten benh nhan", "customer name", "patient name", "holder name", "cardholder name", "account holder"},
		Exclude: []string{"file", "class", "type", "host", "field", "column", "table", "package", "module", "app", "bucket", "method", "func", "function", "event", "screen", "tag", "attr", "attribute", "font", "theme", "bundle"}},
	{ID: "dob", Label: "Date of birth", Category: "identity",
		Patterns: []string{"dob", "date of birth", "birth date", "birthdate", "birthday", "birth day", "ngay sinh", "ngaysinh", "nam sinh", "namsinh", "sinh nhat", "year of birth", "birth year"}},
	{ID: "address", Label: "Postal address", Category: "location",
		Patterns: []string{"street address", "home address", "billing address", "shipping address", "postal address", "mailing address",
			"residential address", "dia chi", "diachi", "thuong tru", "tam tru", "noi o", "que quan", "noi sinh", "zip code", "zipcode", "postal code", "postcode"},
		Weak: []string{"address"},
		Exclude: []string{"ip", "ipv4", "ipv6", "mac", "memory", "wallet", "server", "remote", "local", "bind", "listen", "base", "host",
			"web", "url", "uri", "socket", "net", "network", "peer", "proxy", "gateway", "contract", "email", "mail", "ptr", "pointer", "offset",
			"bluetooth", "ble", "hw", "hardware", "broadcast", "multicast", "sender", "public", "return", "bar", "book", "resolver", "dns", "node", "api", "endpoint", "virtual", "physical"}},
	{ID: "ip_address", Label: "IP address", Category: "online",
		Patterns: []string{"ip address", "ipaddress", "ip addr", "ipaddr", "client ip", "remote ip", "user ip", "remote addr", "remote address", "x forwarded for", "real ip", "dia chi ip"},
		Weak:     []string{"ip"},
		Exclude:  []string{"server", "bind", "listen", "host", "gateway", "dns", "proxy", "subnet", "cidr", "range", "allow", "block", "whitelist", "allowlist"}},
	{ID: "vn_cccd", Label: "Vietnamese citizen ID (CCCD/CMND)", Category: "identity",
		Patterns: []string{"cccd", "so cccd", "socccd", "can cuoc", "cancuoc", "can cuoc cong dan", "cmnd", "so cmnd", "socmnd", "chung minh nhan dan", "chung minh thu", "cmt", "so dinh danh", "ma dinh danh"}},
	{ID: "national_id", Label: "National ID number", Category: "identity",
		Patterns: []string{"national id", "nationalid", "citizen id", "citizenid", "identity number", "identity card", "id card", "idcard", "id number", "nric", "identification number", "personal id", "personal number", "aadhaar"},
		Weak:     []string{"nid", "nin"}},
	{ID: "us_ssn", Label: "US Social Security number", Category: "identity",
		Patterns: []string{"ssn", "social security", "social security number", "ss number"}},
	{ID: "passport", Label: "Passport number", Category: "identity",
		Patterns: []string{"passport", "passport number", "passport no", "ho chieu", "hochieu", "so ho chieu"}},
	{ID: "drivers_license", Label: "Driver's license number", Category: "identity",
		Patterns: []string{"driver license", "drivers license", "driving license", "driving licence", "driver licence", "license number", "giay phep lai xe", "gplx", "bang lai"}},
	{ID: "tax_id", Label: "Tax identification number", Category: "identity",
		Patterns: []string{"tax id", "taxid", "tax code", "taxcode", "tax number", "tax identification", "ma so thue", "masothue"},
		Weak:     []string{"mst", "tin"}},
	{ID: "insurance_id", Label: "Social/health insurance number", Category: "identity",
		Patterns: []string{"bhxh", "so bhxh", "bhyt", "the bhyt", "so bhyt", "bao hiem xa hoi", "bao hiem y te", "social insurance", "health insurance number", "insurance number", "medicare number", "nhs number"}},
	{ID: "credit_card", Label: "Payment card number", Category: "financial", Sensitive: true,
		Patterns: []string{"card number", "cardnumber", "card no", "credit card", "creditcard", "debit card", "cc number", "ccnumber", "cc num", "so the", "cvv", "cvc", "cvv2", "card cvv", "card expiry"},
		Weak:     []string{"pan"},
		Exclude:  []string{"type", "brand", "network", "view", "layout", "icon", "logo", "scheme", "last4", "last", "4", "bin", "masked"}},
	{ID: "bank_account", Label: "Bank account number", Category: "financial", Sensitive: true,
		Patterns: []string{"bank account", "bankaccount", "account number", "accountnumber", "account no", "acct number", "acct no", "iban", "routing number", "so tai khoan", "sotaikhoan", "stk", "tai khoan ngan hang"}},
	{ID: "location", Label: "Precise geolocation", Category: "location", Sensitive: true,
		Patterns: []string{"latitude", "longitude", "lat lng", "latlng", "lat long", "geolocation", "geo location", "gps", "coordinates", "current location", "user location", "last location", "vi tri", "toa do", "kinh do", "vi do"},
		Weak:     []string{"lat", "lng", "lon", "location"},
		Exclude:  []string{"file", "url", "path", "dir", "header", "bucket", "storage", "code", "source", "line", "column", "offset", "permission", "service", "manager", "enabled", "settings", "request", "provider", "client"}},
	{ID: "device_id", Label: "Device / advertising identifier", Category: "device",
		Patterns: []string{"imei", "imsi", "android id", "androidid", "device id", "deviceid", "idfa", "idfv", "gaid", "advertising id", "advertisingid", "ad id", "adid", "udid",
			"mac address", "macaddress", "hardware id", "fcm token", "push token", "device token", "registration token", "serial number", "ma thiet bi"},
		Exclude: []string{"type", "model", "name", "os", "kind"}},
	{ID: "gender", Label: "Gender", Category: "demographic",
		Patterns: []string{"gender", "gioi tinh", "gioitinh"},
		Weak:     []string{"sex"}},
	{ID: "ethnicity", Label: "Ethnicity / race", Category: "demographic", Sensitive: true,
		Patterns: []string{"ethnicity", "ethnic", "ethnic group", "dan toc", "dantoc"},
		Weak:     []string{"race"},
		Exclude:  []string{"condition", "data", "detector", "check", "trace"}},
	{ID: "religion", Label: "Religion", Category: "demographic", Sensitive: true,
		Patterns: []string{"religion", "religious", "ton giao", "tongiao"}},
	{ID: "health", Label: "Health data", Category: "health", Sensitive: true,
		Patterns: []string{"diagnosis", "medical record", "medical history", "health record", "health condition", "blood type", "prescription", "medication",
			"allergy", "allergies", "disease", "icd10", "benh an", "chan doan", "tien su benh", "don thuoc", "nhom mau", "tinh trang suc khoe"},
		Exclude: []string{"code", "service", "api", "check", "endpoint"}},
	{ID: "biometric", Label: "Biometric data", Category: "biometric", Sensitive: true,
		Patterns: []string{"biometric", "biometrics", "face template", "face embedding", "face vector", "face id", "faceprint", "fingerprint template", "fingerprint image",
			"voiceprint", "voice print", "iris scan", "van tay", "khuon mat", "sinh trac hoc"}},
	{ID: "license_plate", Label: "Vehicle license plate", Category: "identity",
		Patterns: []string{"license plate", "licence plate", "plate number", "number plate", "bien so", "bien so xe", "bienso"}},
}
