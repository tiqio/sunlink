package main

import (
	"fmt"
	"net"
)

func main() {
	// 监听 UDP 地址
	conn, err := net.ListenPacket("udp", ":12345") // 使用端口 12345
	if err != nil {
		fmt.Printf("Error listening: %v\n", err)
		return
	}
	defer conn.Close()

	buffer := make([]byte, 1024) // 创建一个缓冲区接收数据

	for {
		n, addr, err := conn.ReadFrom(buffer) // 从连接中读取数据
		if err != nil {
			fmt.Printf("Error reading: %v\n", err)
			continue
		}
		fmt.Printf("Received %d bytes from %s: %v\n", n, addr.String(), buffer[:n])
	}
}
