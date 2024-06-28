package config

type ConfigField interface {
	Required() bool
	Description() string
	FieldName() string
}

type StringField struct {
	required     bool
	description  string
	fieldName    string
	defaultValue string
	// Value string
}

func (f *StringField) Required() bool {
	return f.required
}
func (f *StringField) Description() string {
	return f.description
}
func (f *StringField) FieldName() string {
	return f.fieldName
}
func NewStringField(name string, description string, required bool, defaultValue string) *StringField {
	return &StringField{
		required:     required,
		description:  description,
		fieldName:    name,
		defaultValue: defaultValue,
	}
}

type BoolField struct {
	required     bool
	description  string
	fieldName    string
	defaultValue bool
}

func (f *BoolField) Required() bool {
	return f.required
}
func (f *BoolField) Description() string {
	return f.description
}
func (f *BoolField) FieldName() string {
	return f.fieldName
}
func NewBoolField(name string, description string, required bool, defaultValue bool) *BoolField {
	return &BoolField{
		required:     required,
		description:  description,
		fieldName:    name,
		defaultValue: defaultValue,
	}
}

type IntField struct {
	Required     bool
	Description  string
	FieldName    string
	DefaultValue int
}

type BaseConfig struct {
	LogLevel ConfigField
	Timeout  ConfigField
}

type Config struct {
	BaseConfig
	ConfigFields map[string]ConfigField
}

// var Cfg Config = Config{
// 	BaseConfig: BaseConfig{
// 		LogLevel: NewStringField("log-level", "Log level for the application", false, "debug"),
// 	},
// 	// LogLevel: &ConfigItem{
// 	// 	Required:    false,
// 	// 	Description: "Log level for the application",
// 	// 	FieldName:   "log-level",
// 	// 	Field: NewStringField{
// 	// 		defaultValue: "debug",
// 	// 	},
// 	// },
// 	// Timeout: &ConfigItem{
// 	// 	Required:    false,
// 	// 	Description: "Timeout for the application",
// 	// 	FieldName:   "timeout",
// 	// 	Field: IntField{
// 	// 		DefaultValue: 10,
// 	// 	},
// 	// },
// }
