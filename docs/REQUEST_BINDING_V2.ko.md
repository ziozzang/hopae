# 순수 request binding v2

추가 SDK module `hopae_grpc::request_binding_v2`이며 기존 v1 source·golden vector는 그대로다. Human 인증·receipt·prepared proof·활성 RPC·권한 capability가 아닌 순수 codec이다.

`HeaderPolicy::new(revision,names,reserved_names)`는 고정 서버 설정의 소문자 RFC tchar 이름(1..128byte)을 정렬한다. revision1..9007199254740991, 빈 manifest 허용·최대16slot/64reserved이며 중복·잘못된 이름·보안/framing/hop/identity 기본 필드·설정 reserved 충돌은 이름 복사 전에 거부한다. 모든 custom caller/projected credential/identity 이름은 소유자가 reserved에 지정해야 하며 codec이 추측하지 않는다. 무관한 실제 header는 bound-slot DTO 밖에 있다.

`digest(&HeaderPolicy,&Request)`는 실제 완전한 `body:&[u8]`에서 길이/SHA256을 복사 없이 계산하며 raw bodydigest 입력 API는 없다. 정확히16MiB까지 허용한다. service/audience/routeID·revision·nonzero destinationSHA·method·정확한 origin-form target을 묶으며 경로/query/percent 정규화는 없다. destination 원천 소유권은 native owner 책임이며 hash가 증명하지 않는다.

각 고정 slot은 `BoundHeader{name,value:Option<&[u8]>}`에 정확히 한 번 등장한다. None/빈 present를 구분하고 순서는 compiled manifest에 따라 정렬한다. 알 수 없는·중복·누락 slot은 거부한다. 값은 obs-text까지 원본을 보존하되 TAB·DEL 포함CTL은 거부하고 각1024/합8192byte 이하이다. Request/BoundHeader Debug는 내용을 가린다. 이 데이터로 native grant를 만들지 않는다.

정규 encoding·독립 Python reference는 공개 ZT98874bc의 `docs/reviews/2026-10-16-request-binding-v2.md`, `tools/request_binding_v2_reference.py`이다. synthetic `fixtures/request-binding-v2.json` SHA2562965d4c2eaeaed39a866758aa13d9c7a9d43393908c3507dc90ee175c68a1352를 그대로 복사해 독립 expected SHA7개와 대조한다. v2NUL domain, LP32 text와 고정 BEu64 revision/bodylength·raw32hash·BEu16slotcount, 정렬된 LP32name/presenceu8/present일때LP32value를 사용한다.

빈/실제body·같은 길이 변조·route/destination/method/query/basepath·slot순서/absence/empty·reserved/중복/unknown·CTL·한계를 검증한다. codec source 검증이며 Human wire/product·runtime owner·전체 경로 검증이 아니다. proto·기존 receipt검증·Service/Workload 의미·clock·runtime활성화는 변경하지 않는다.
