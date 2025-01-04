## 网络安全程序设计

1.	cd ./myfw_mod
	insmod myfw.ko
	# 可通过dmesg查看内核输出提示信息
2.	cd ./myfw_app
	gcc -o kt_app kt_app.c
	./kt_app
