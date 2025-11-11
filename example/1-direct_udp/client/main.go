package main

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

func main() {
	conn, err := net.ListenPacket("udp", "127.0.0.1:33333")
	if err != nil {
		fmt.Printf("conn err: %v\n", err)
		return
	}
	defer conn.Close() // 确保连接在程序结束时关闭

	uAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:12345") // 服务器地址
	if err != nil {
		fmt.Printf("Error resolving address: %v\n", err)
		return
	}

	var data = []byte{1}
	var i = 1
	for {
		i++
		data = append(data, byte(i))        // 附加数据
		_, err := conn.WriteTo(data, uAddr) // 发送数据
		if err != nil {
			fmt.Printf("Error writing to server: %v\n", err)
			return
		}
		time.Sleep(5 * time.Second) // 每隔 5 秒发送一次
		fmt.Println("Connection write: " + strconv.Itoa(i))
	}
}
