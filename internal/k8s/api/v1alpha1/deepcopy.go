package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func (in *GrantoryHost) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(GrantoryHost)
	*out = *in
	out.ObjectMeta = *in.ObjectMeta.DeepCopy() //nolint:staticcheck
	out.Spec.Labels = copyStringMap(in.Spec.Labels)
	out.Status.Conditions = copyConditions(in.Status.Conditions)
	return out
}

func (in *GrantoryHostList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(GrantoryHostList)
	*out = *in
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]GrantoryHost, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *in.Items[i].DeepCopyObject().(*GrantoryHost)
		}
	}
	return out
}

func (in *GrantoryRequest) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(GrantoryRequest)
	*out = *in
	out.ObjectMeta = *in.ObjectMeta.DeepCopy() //nolint:staticcheck
	out.Spec.Labels = copyStringMap(in.Spec.Labels)
	out.Spec.GrantOutputKeys = copyStringMap(in.Spec.GrantOutputKeys)
	out.Spec.Payload = copyRawExtension(in.Spec.Payload)
	out.Status.GrantPayload = copyRawExtension(in.Status.GrantPayload)
	out.Status.Conditions = copyConditions(in.Status.Conditions)
	if in.Spec.HostRef != nil {
		hostRef := *in.Spec.HostRef
		out.Spec.HostRef = &hostRef
	}
	return out
}

func (in *GrantoryRequestList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(GrantoryRequestList)
	*out = *in
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]GrantoryRequest, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *in.Items[i].DeepCopyObject().(*GrantoryRequest)
		}
	}
	return out
}

func (in *GrantoryRegister) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(GrantoryRegister)
	*out = *in
	out.ObjectMeta = *in.ObjectMeta.DeepCopy() //nolint:staticcheck
	out.Spec.Labels = copyStringMap(in.Spec.Labels)
	out.Spec.Payload = copyRawExtension(in.Spec.Payload)
	out.Status.Conditions = copyConditions(in.Status.Conditions)
	if in.Spec.HostRef != nil {
		hostRef := *in.Spec.HostRef
		out.Spec.HostRef = &hostRef
	}
	return out
}

func (in *GrantoryRegisterList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(GrantoryRegisterList)
	*out = *in
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]GrantoryRegister, len(in.Items))
		for i := range in.Items {
			out.Items[i] = *in.Items[i].DeepCopyObject().(*GrantoryRegister)
		}
	}
	return out
}

func copyStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func copyConditions(input []metav1.Condition) []metav1.Condition {
	if input == nil {
		return nil
	}
	out := make([]metav1.Condition, len(input))
	copy(out, input)
	return out
}

func copyRawExtension(input runtime.RawExtension) runtime.RawExtension {
	if len(input.Raw) == 0 {
		return runtime.RawExtension{}
	}
	return runtime.RawExtension{Raw: append([]byte(nil), input.Raw...)}
}
