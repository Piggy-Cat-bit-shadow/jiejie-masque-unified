package main

import "fmt"

func formatSocketBufferLog(pre, post socketBufferSizes, requested int) string {
	return fmt.Sprintf("CONNECT-IP UDP socket buffers: pre_rcv=%d pre_send=%d post_rcv=%d post_send=%d requested=%d", pre.Receive, pre.Send, post.Receive, post.Send, requested)
}
