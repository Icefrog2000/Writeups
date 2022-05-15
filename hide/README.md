## Write-Up Hide (HCMUS CTF 2022 - Reverse)

Bài ảo ma nhất trong cả giải. Dịch ngược 1 file ELF, file này có vẻ nó ko gọi các hàm libc mà dùng syscall. Khi đang debug được 1 lúc bằng gdb sẽ thầy nó tự thực thi mà chả hiểu tại sao, hoặc tự nhiên lăn đùng ra bị Segfault. Nên mình đoán là có Anti-Debug. Debug sẽ thấy nó mmap cái gì đó, xong rồi copy asm code lên địa chỉ được mmap rồi làm cái gì đó, đoán lờ mờ khả năng nó đang unpack hoặc là đơn giản là thực thi shellcode.

Cách tiếp cận tốt nhất nên là dùng `strace` để trace các syscall, và nhận được một số thứ hay ho

![image](https://user-images.githubusercontent.com/54637811/168479238-17de9016-32ca-4f7e-b7f7-cfa50ef46b50.png)

Nó có 1 đoạn `readlink("/proc/self/exe")`, mình search thì biết đấy là kiểu anti-debug, hàm readlink có tham số là 1 file symbol link và trả về đường dẫn của thực sự mà cái file symbol link kia liên kết tới.

Nếu đang dùng debug thì nó sẽ trả về đường dẫn của gdb chứ ko phải đường dẫn của file hide. Cơ mà lý thuyết là thế chứ lúc mình debug nó vẫn trả về đường dẫn của hide :v

Bên cạnh `readlink` thì nó còn dùng `arch_prctl`, cái này để đổi giữa 32 bit và 64 bit trong lúc chạy, mục đích để khiến lúc disassembly 1 kiểu nhưng lúc chạy thì lại kiểu khác. Chắc đây là nguyên nhân khiến mình ăn Segfault khi mình đặt breakpoint ko đúng chỗ.

Cuối cùng nó thực thi syscall read để đọc input ở địa chỉ `0000000000455b42`, địa chỉ này được sinh ra bởi mmap, nên chắc chắn là nó đang unpack luôn

Kế hoạch sẽ là:
+ Đặt cái breakpoint tại `00000000005168a2`, nơi xảy ra `mmap` đầu tiên
+ Đặt cái hardware breakpoint tại `0000000000455b42`, nơi xảy ra `read`. À nhớ là bật cái này trong gdb `set breakpoint pending on` để nó đặt breakpoint tại địa chỉ chưa tồn tại. Tại sao không đặt thằng luôn mà đặt tại `00000000005168a2` làm gì, thì mình cũng làm rồi nhưng nó không chạy tới dc chỗ `read`. Câu lệnh sẽ là `hb*0x0000000000455b42`

<img src="https://user-images.githubusercontent.com/54637811/168479839-f05bc78a-2022-4bf6-9a72-6ad1308e04bc.png" width="600" height="300"/>

Ok chúng ta đã đi tới được hàm read, `vmmap` xem đã

<img src="https://user-images.githubusercontent.com/54637811/168480009-03a1b04b-3feb-4f8d-b922-77c7105e5635.png" width="600" height="250"/>

Dựa vào `strace` và `vmmap` ta thấy địa chỉ 0x400000 đáng nghi, vì đây là đỉa chỉ ưa thích của file ELF 64 bit. Hexdump xem cho chắc

![image](https://user-images.githubusercontent.com/54637811/168480158-08e436f0-e37c-4050-9a25-5bba9674f601.png)

Ok game là dễ, dump thôi: `dump dump_file 0x400000 0x4ca000`

Ta được cái dump_file, vứt nó vào IDA để phân tích
