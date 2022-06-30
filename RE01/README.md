Ok đây là Write-up vội bài dịch ngược cuối để lấy 200k.
Mới mở trong IDA thấy ngay nó lấy gì đó trong Resourse, dump nó ra rồi mở nó trong HxD cộng với việc nhìn trong IDA ta thấy nó là shellcode. Ta dùng tools shellcode2exe để chuyển shellcode sang exe tiện phân tích.
![image](https://user-images.githubusercontent.com/54637811/176706290-ae208d88-30e5-46a2-93c4-5c579f5882d8.png)

Ok chúng ta thấy có vẻ nó đang cố tìm các hàm:
Sleep, LoadLibraryA, VirtualAlloc, VirtualProtect, FlushInstructionCache, GetNativeSystemInfo, RtlAddFunctionTable
Mình chưa biết cái đoạn dưới nó làm cái gì. Cứ đặt breakpoint tại VirtualProtect xem thế nào

![image](https://user-images.githubusercontent.com/54637811/176709305-a373e983-0c79-42c4-a966-79dc826feebf.png)
Mình thấy nó khở tạo địa chỉ từ 0x180000000 đến 0x18000a000. Ok lại một cái PE nữa.
Trong đầu mình lúc này là dump nó ra, nhưng chẳng hiểu sao giá trị dump ra lại khác trên bộ nhớ, mình đã thử dump bằng x64dbg, Process Hacker đều ra kết quả sai.
Đến lúc này mình mới nhớ đã đọc một bài báo của team Mandiant
https://www.mandiant.com/resources/debugging-complex-malware-that-executes-code-on-the-heap
Bài báo giới thiệu một tính năng:
![image](https://user-images.githubusercontent.com/54637811/176710255-0d81b809-ee05-4927-b493-37cd40225f9f.png)
Nó giúp lưu các segment code được tạo ra trong quá trình debug vào database, giúp ta có thể phân tích tĩnh sau khi kết thúc debug.
Xong reanalyze lại toàn bộ database ida:
![image](https://user-images.githubusercontent.com/54637811/176710555-18812929-729b-4f88-a285-c5b25960aa32.png)
Ta lướt xuống dưới pseudocode của hàm sub_401040, ta đoán có thể chỗ này chính là lúc call entry point của cái PE mới được tạo ra
đặt breakpoint vào đó
![image](https://user-images.githubusercontent.com/54637811/176711146-0dd56bc1-f38d-49fa-81e5-00b985adc955.png)
![image](https://user-images.githubusercontent.com/54637811/176711235-7c115ea1-f603-414f-9978-ecd80f7beafd.png)

Ok ta đã đến được entry point:
![image](https://user-images.githubusercontent.com/54637811/176711445-6711f3ab-147c-4267-856f-21bfa9b3bdf1.png)
Cái đoạn security_init_cookie là do mình đổi tên được nhé, mọi người có thể tạo ra một file x64 mới, build bằng visual studio rồi đem so sánh hàm start của cái PE mới này so với hàm start của file mới được build bằng visual studio để xem main ở đâu.
Sau một hồi mình cũng không đoán được main ở đâu :D. Mình đang đi loanh quanh thì tìm tới được IAT của cái PE này
![image](https://user-images.githubusercontent.com/54637811/176712213-5c0eaf00-59b2-49fd-9294-247e370b8bcc.png)
Gộp 8 bytes lại với nhau thì IDA sẽ cho mình biết đây là ô IAT của hàm nào. Lướt qua cái IAT này thì tự nhiên mình thấy nó có hàm vfprintf và vfscanf
![image](https://user-images.githubusercontent.com/54637811/176712605-d2068811-f14f-49e8-a714-c03a4288bcf9.png)

Ngon, đổi tên 2 hàm gọi vfprintf và vfscanf thành printf và scanf.
printf được tham chiếu 3 nơi, scanf thì chỉ một. Lần theo scanf thì nó dẫn mình tới hàm này
![image](https://user-images.githubusercontent.com/54637811/176713094-9042f513-869b-4208-a142-3e3e652a4ec7.png)
Mình nghĩ cái này là main chắc rồi, vì hàm gọi nó có vẻ giống seh_main_common.

Đập vào mắt lại là một cái antidebug
![image](https://user-images.githubusercontent.com/54637811/176713339-437bc50b-9cb1-4dba-a7a4-86d5587e6a57.png)
Nhưng rất tiếc, mình dùng plugin ScyllaHide tự đông bypass mấy cái antidebug đơn giản nên mình cũng không care lắm :D.
Mình quan tâm mấy dòng cuối thôi
![image](https://user-images.githubusercontent.com/54637811/176713594-c564f237-44df-420b-b1bc-34216842800b.png)
Kiểm tra xem hàm check nó làm cái gì:
![image](https://user-images.githubusercontent.com/54637811/176713741-1bab3208-16e3-4f35-a224-b0457ec1764e.png)
Mình thấy nó đang cố lấy hàm nào đó bằng GetProcAddress, debug thì biết nó đang lấy hàm IsDebugPresent, mình không quan tâm :D.
Chúng ta chỉ cần quan tâm đoạn này
![image](https://user-images.githubusercontent.com/54637811/176714137-3dc325b4-d013-4557-88b4-a61fea2bc300.png)
OK đầu tiên là mình thấy nó cộng trừ nhân chia liên quan đến 4 và 16 rất nhiều, mình đoán khả năng là AES. Nhưng có một đoạn mình rất lăn tăn, nếu đây là AES thì khả năng sub_180001000 là hàm mở rộng khoá, cơ mà v49 lại là mảng 176 byte, tức là nếu khoá dài 16 byte thì sẽ có 11 round.
Mình nghĩ là chắc sai rồi, làm gì có AES nào 11 round. :>
Thế là mình mất thêm 1-2 tiếng nó cố phân tích tĩnh. Phân tích sâu hơn nó dẫn mình tới cái bảng này
![image](https://user-images.githubusercontent.com/54637811/176714922-bb527e8e-8ff7-4c9d-9fc9-edec0a03e51e.png)
Lên mạng search thì Google bảo đây là S-box của AES, vl :D.
Thế là mình nhảy lại hàm mở rộng khoá, debug vào xem đầu ra:
![image](https://user-images.githubusercontent.com/54637811/176715374-6eba2230-a7da-4930-baf7-f7fa0ce5490c.png)
Đây là 176 byte được sinh ra, nhưng 16 byte đầu chính là input của hàm mở rộng khoá nên mình đoán là ông tác giả copy 16 bytes khoá vào trước rồi copy 160 bytes được mở rộng vào sau nên mới có chuyện 176 bytes.
Vậy key AES là b'\xac\xc3W\xa2Z"8\xbet\x1e8\'\xb2\x98\xb4\xa2'

Quay lại cái vòng lặp:
![image](https://user-images.githubusercontent.com/54637811/176715776-2090d45f-4548-4b68-b06d-ba0eeb1abe36.png)

Ta đoán được khả năng mode là CBC và hàm sub_180001410 là hàm mã hoá khối AES, iv sẽ là mảng v31, hay chính là tham số a4: a4 = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'
Ok đi qua được đoạn AES là 1 đoạn xor bình thường:
![image](https://user-images.githubusercontent.com/54637811/176716283-a088ed0b-4444-4516-ac7a-98cb60a62c0a.png)
Đây là code giải mã của mình:
```python
from Crypto.Cipher import AES

a4 = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'
key = b'\xac\xc3W\xa2Z"8\xbet\x1e8\'\xb2\x98\xb4\xa2'
result = list(b'\x14\xd5D\xb4\x18*\x9d%@M\x07\xcf6\x0c-Y\x0f\x1b\x96`-\x1b\xaf&\xbc\xf7Bc{jB><\xb4`\xfd\x029\\\n\x84\xc0\xa5\x8b\x14n\xbf\xa9\x9e\xc3\xde]Z-4\xb21\xf0\xddw*\xa7Y\xda')
xored = list(b'7\x95\xack"A\xb3@\xacTZ\xa8\x9bV,=t\xa6m\x88Z8V3jX_\xb6\t\x87c\xc50P\x03z\xba\xa8\xb0\xa4\x14\x88\xc5\x03g*\x9a\x8cd\xa4\xa3\x04N\xb3-\x81\x88pp_\xc55\x90&')
input = b'977330285cd3cb4bfb15b09d132fae6ffe533729a21ce274f325440827164cc7'
cipher = AES.new(key, AES.MODE_CBC, iv=a4)
for i in range(64):
    result[i] ^= xored[i]

print(cipher.decrypt(bytes(result)))
```
