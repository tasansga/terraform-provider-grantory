package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	GroupName = "grantory.ansgar.tasler.net"
	Version   = "v1alpha1"
)

var (
	GroupVersion  = schema.GroupVersion{Group: GroupName, Version: Version}
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

type HostRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type GrantoryHostSpec struct {
	UniqueKey       string            `json:"uniqueKey,omitempty"`
	GrantoryHostID  string            `json:"grantoryHostID,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	DeleteOnRemoval bool              `json:"deleteOnRemoval,omitempty"`
}

type GrantoryHostStatus struct {
	ID                 string             `json:"id,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

type GrantoryHost struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GrantoryHostSpec   `json:"spec,omitempty"`
	Status GrantoryHostStatus `json:"status,omitempty"`
}

type GrantoryHostList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GrantoryHost `json:"items"`
}

type GrantoryRequestSpec struct {
	HostID                    string               `json:"hostID,omitempty"`
	HostRef                   *HostRef             `json:"hostRef,omitempty"`
	UniqueKey                 string               `json:"uniqueKey,omitempty"`
	RequestSchemaDefinitionID string               `json:"requestSchemaDefinitionID,omitempty"`
	GrantSchemaDefinitionID   string               `json:"grantSchemaDefinitionID,omitempty"`
	GrantOutputKind           string               `json:"grantOutputKind,omitempty"`
	GrantOutputName           string               `json:"grantOutputName,omitempty"`
	GrantOutputKeys           map[string]string    `json:"grantOutputKeys,omitempty"`
	Payload                   runtime.RawExtension `json:"payload,omitempty"`
	Labels                    map[string]string    `json:"labels,omitempty"`
	DeleteOnRemoval           bool                 `json:"deleteOnRemoval,omitempty"`
}

type GrantoryRequestStatus struct {
	ID                 string               `json:"id,omitempty"`
	HasGrant           bool                 `json:"hasGrant,omitempty"`
	GrantID            string               `json:"grantID,omitempty"`
	GrantPayload       runtime.RawExtension `json:"grantPayload,omitempty"`
	ObservedGeneration int64                `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition   `json:"conditions,omitempty"`
}

type GrantoryRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GrantoryRequestSpec   `json:"spec,omitempty"`
	Status GrantoryRequestStatus `json:"status,omitempty"`
}

type GrantoryRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GrantoryRequest `json:"items"`
}

type GrantoryRegisterSpec struct {
	HostID             string               `json:"hostID,omitempty"`
	HostRef            *HostRef             `json:"hostRef,omitempty"`
	UniqueKey          string               `json:"uniqueKey,omitempty"`
	SchemaDefinitionID string               `json:"schemaDefinitionID,omitempty"`
	Payload            runtime.RawExtension `json:"payload,omitempty"`
	Labels             map[string]string    `json:"labels,omitempty"`
	DeleteOnRemoval    bool                 `json:"deleteOnRemoval,omitempty"`
}

type GrantoryRegisterStatus struct {
	ID                 string             `json:"id,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

type GrantoryRegister struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GrantoryRegisterSpec   `json:"spec,omitempty"`
	Status GrantoryRegisterStatus `json:"status,omitempty"`
}

type GrantoryRegisterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GrantoryRegister `json:"items"`
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&GrantoryHost{},
		&GrantoryHostList{},
		&GrantoryRequest{},
		&GrantoryRequestList{},
		&GrantoryRegister{},
		&GrantoryRegisterList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
