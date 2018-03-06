package tlv

// This file contains debug purpose function(s)

import "fmt"

func printTlv(data T8L16, level uint) {
	for len(data) > 0 {
		t, v, rest, err := data.Read()
		if err != nil {
			fmt.Printf("%v", rest)
			return
		}

		fmt.Printf("\n%*d:", 8*level, t)
		printTlv(v, level+1)
		data = rest
	}

	if level != 0 {
		return
	}
	fmt.Println()
}
