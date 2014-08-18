package main

import "fmt"

const maxPrintLen = 100

type Problem func() (string, error)

func main() {
	for _, p := range []struct {
		id int
		f  Problem
	}{
		{1, Problem1},
		{2, Problem2},
		{3, Problem3},
		{4, Problem4},
		{5, Problem5},
		{6, Problem6},
		{7, Problem7},
		{8, Problem8},
		{9, Problem9},
		{10, Problem10},
		{11, Problem11},
		{12, Problem12},
		{13, Problem13},
		{14, Problem14},
	} {
		fmt.Printf("%-2d ", p.id)
		color := "\033[92m"
		msg, err := p.f()
		if err != nil {
			color = "\033[91m"
			msg = fmt.Sprintf("Error: %s", err)
		}
		// Don't print the whole thing if it's long. (Like the lyrics to an entire song...)
		if len(msg) > maxPrintLen {
			msg = msg[:maxPrintLen-5] + "[...]"
		}
		fmt.Printf("%s%s\033[0m\n", color, msg)
	}
}
