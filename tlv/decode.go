package tlv

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/cloudcopper/core/encoding/binary"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"
)

// Decode YAML into generic TLV structure
func Decode(str string) (Elements, error) {
	node := yaml.Node{}
	if err := yaml.Unmarshal([]byte(str), &node); err != nil {
		return nil, errors.WithStack(err)
	}

	out := Elements{}
	err := decodeYamlDocument(&node, &out)
	return out, err
}

func decodeYamlDocument(node *yaml.Node, out *Elements) error {
	if node.Kind != yaml.DocumentNode {
		return errors.WithStack(errNoYamlDocumentNode)
	}

	err := decodeYamlContent(node.Content, out)
	return err
}

func decodeYamlContent(nodes []*yaml.Node, out *Elements) error {
	var err error
	index := 0
	for index < len(nodes) {
		index, err = decodeYamlNode(nodes, index, out)
		if err != nil {
			return err
		}
	}

	return nil
}

func decodeYamlNode(nodes []*yaml.Node, index int, out *Elements) (int, error) {
	n := nodes[index]
	if n == nil {
		return index + 1, nil
	}

	switch n.Kind {
	case yaml.MappingNode:
		return decodeYamlNodeMapping(nodes, index, out)
	case yaml.ScalarNode:
		// TLV Type
		if err := decodeYamlAppendElement(nodes[index+0], out); err != nil {
			return index, err
		}
		// TLV Value
		if err := decodeYamlSetElementValue(nodes[index+1], out); err != nil {
			return index, err
		}
		return index + 2, nil
	}

	return index, errors.WithStack(errUnsupportedYamlNodeKind)
}

func decodeYamlNodeMapping(nodes []*yaml.Node, index int, out *Elements) (int, error) {
	n := nodes[index]

	if len(n.Content)%2 != 0 {
		return index, errors.WithStack(errYamlMappingNodeWrongContentSize)
	}

	for i := 0; i < len(n.Content); i += 2 {
		// TLV Type
		if err := decodeYamlAppendElement(n.Content[i+0], out); err != nil {
			return index, err
		}
		// TLV Value
		if err := decodeYamlSetElementValue(n.Content[i+1], out); err != nil {
			return index, err
		}
	}

	return index + 1, nil
}

var reKey = regexp.MustCompile(`(.*)\(([0-9]*)\).*`)

func decodeYamlAppendElement(node *yaml.Node, out *Elements) error {
	name := ""
	//
	// TLV Type
	//
	s := node.Value

	// try plain integer
	t, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		// try "Text(integer)"
		m := reKey.FindAllStringSubmatch(s, -1)
		if len(m) != 1 || len(m[0]) != 3 {
			return errors.WithStack(errUnsupportedKey)
		}
		name = m[0][1]
		s = m[0][2]
		if s == "" {
			return errors.WithStack(errUnsupportedKey)
		}
		t, err = strconv.ParseUint(s, 0, 64)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	*out = append(*out, Element{name, int(t), nil, nil})
	return nil
}

func decodeYamlSetElementValue(node *yaml.Node, out *Elements) error {
	switch {
	case (node.Kind == yaml.MappingNode) || (node.Kind == yaml.SequenceNode && node.Style == 0): // nested TLVs
		values := Elements{}
		err := decodeYamlContent(node.Content, &values)
		if err != nil {
			return err
		}
		(*out)[len(*out)-1].Sub = values

	case node.Kind == yaml.SequenceNode && node.Style == yaml.FlowStyle: // array of V
		value, err := decodeYamlArray(node)
		if err != nil {
			return err
		}
		(*out)[len(*out)-1].V = value

	case node.Kind == yaml.ScalarNode:
		value, err := decodeYamlValue(node)
		if err != nil {
			return err
		}
		(*out)[len(*out)-1].V = value

	default:
		return errors.WithStack(errUnsupportedYamlNodeKind)
	}

	return nil
}

func decodeYamlArray(node *yaml.Node) (T8L16, error) {
	v := make(T8L16, 0, 16)
	for _, n := range node.Content {
		a, err := decodeYamlValue(n)
		if err != nil {
			return nil, err
		}
		v = append(v, a...)
	}
	return v, nil
}

func decodeYamlValue(node *yaml.Node) (T8L16, error) {
	s := node.Value

	if node.Style == yaml.DoubleQuotedStyle {
		return T8L16(s), nil
	}

	// try to guess type
	if mac, err := net.ParseMAC(s); err == nil {
		return T8L16(mac), nil
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); len(ip4) == net.IPv4len {
			return T8L16(ip4), nil
		}
		return T8L16(ip), nil
	}
	if u, err := parseUint16(s); err == nil {
		v := T8L16{0, 0}
		binary.NetworkByteOrder.PutUint16(v, u)
		return v, nil
	}
	if s == "null" {
		return T8L16{}, nil
	}
	if s == "true" {
		return T8L16{1}, nil
	}
	if s == "false" {
		return T8L16{0}, nil
	}

	// fallback to byte
	n, err := strconv.ParseUint(s, 0, 8)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return T8L16{byte(n)}, nil
}

// The parseSliceOfBytes function parses string representation of byte slice
func parseSliceOfBytes(s string) ([]byte, error) {
	// Check preconditions
	if len(s) == 0 {
		return nil, errors.WithStack(errCanNotParseSliceOfBytes)
	}
	if s[0] != '[' {
		return nil, errors.WithStack(errCanNotParseSliceOfBytes)
	}
	if s[len(s)-1] != ']' {
		return nil, errors.WithStack(errCanNotParseSliceOfBytes)
	}

	//
	res := make([]byte, 0, 32)
	a := strings.Split(s[1:len(s)-1], ",")
	if len(a) == 1 && a[0] == "" { // special case to define empty slice
		return res, nil
	}
	for _, s := range a {
		n, err := strconv.ParseUint(s, 0, 8)
		if err != nil {
			return res, errors.WithStack(err)
		}
		res = append(res, byte(n))
	}

	return res, nil
}

// The parseUint16 function parses uint16 string in form of "uint16(1234)"
func parseUint16(s string) (uint16, error) {
	if len(s) < 8 {
		return 0, errors.WithStack(errStringTooShort)
	}
	if s[:7] != "uint16(" && s[len(s)-1] != ')' {
		return 0, errors.WithStack(errWrongFormat)
	}

	s = s[7 : len(s)-1]
	n, err := strconv.ParseUint(s, 0, 16)
	return uint16(n), errors.WithStack(err)
}
