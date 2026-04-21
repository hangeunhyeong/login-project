// AccessToken 만료시 Refreshing
export async function refreshAccessToken(){
    // 로컬 스토리지로부터 RefreshToken 가져옴
    const refreshToken = localStorage.getItem("refreshToken");
    if(!refreshToken)   throw new Error("RefreshToken이 없습니다.");

    const response = await fetch(`${import.meta.env.VITE_BACKEND_API_BASE_URL}/jwt/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({refreshToken}),
    });

    if(!response.ok)    throw new Error("AccessToken 갱신 실패");

    // 성공시 새 Token 저장 
    const data = await response.json();
    localStorage.setItem("accessToken", data.accessToken);
    localStorage.setItem("refreshToken", data.refreshToken);

    return data.accessToken;
}
// accessToken과 함께 fetch(options는 credential, header와 같은 헤더설정을 포함)
export async function fetchWithAccess(url, options = {}){
    // 로컬 스토리지로부터 AccessToken 가져옴
    let accessToken = localStorage.getItem("accessToken");
    if(accessToken == null) console.log("로컬스토리지에 accessToken 비어있음");

    // 옵션에 Header 없는 경우 추가 + AccessToken 부착
    if(!options.headers)    options.headers = {};
    options.headers['Authorization'] = `Bearer ${accessToken}`;

    // 요청 진행
    let response = await fetch(url, options);

    // AccessToken 만료로 401 뜨면, Refresh 로 재발급
    if(response.status === 401){
        try{
            alert("401 오류");
            accessToken = await refreshAccessToken();
            options.headers['Authorization'] = `Bearer ${accessToken}`;

            // 재요청
            response = await fetch(url, options);
            if(response == null)    alert("응답없음")
        }catch(err){
            // Refreshing이 실패했기 때문에 로컬스토리지 삭제후 로그인 페이지로
            localStorage.removeItem("accessToken");
            localStorage.removeItem("refreshToken");
            location.href = '/login'    // 로그인 페이지로 redirection
        }
    }
    if(!response.ok){
        throw new Error(`HTTP 오류 : ${response.status}`);
    }
    return response;
}