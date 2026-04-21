import { useNavigate } from "react-router-dom";
import { useEffect } from "react";
const BACKEND_API_BASE_URL = import.meta.env.VITE_BACKEND_API_BASE_URL;

function CookiePage(){
    const navigate = useNavigate();

    // 페이지 접근시 (백엔드에서 리디렉션으로 여기로 보내면 실행)
    useEffect(() => {
        const cookieToBody = async () => {
            // 요청
            try{
                // 백엔드에서 쿠키에 있는 refreshToken, accessToken을 추출하여 응답 body에 담아줌
                const res = await fetch(`${BACKEND_API_BASE_URL}/jwt/exchange`, {
                    method: "POST",
                    headers:    {"Content-Type": "application/json"},
                    credentials: "include", // 로그인 정보도 같이 보낸다(쿠키도 포함되어있음-쿠키의 자동전송 특징)
                });

                if(!res.ok) throw new Error("인증 실패");

                const data = await res.json();
                localStorage.setItem("accessToken", data.accessToken);
                localStorage.setItem("refreshToken", data.refreshToken);
                
                // navigate("/user");
            }catch(err){
                alert("소셜 로그인 실패");
                navigate("/login");
            }
        };

        cookieToBody();
    }, [navigate]);
    return (
        <p>로그인 처리 중입니다...</p>
    );
}

export default CookiePage;