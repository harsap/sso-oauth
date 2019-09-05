package com.tdi.sso.model;

public class Token {
	private String authId;
	private String tokenId;
	private String tokenData;
	private String userName;
	private String clientId;
	private String authentication;
	private String refreshToken;
	private String ipAddress;

	
	
	@Override
	public String toString() {
		return "Token [authId=" + authId + ", tokenId=" + tokenId + ", tokenData=" + tokenData + ", userName="
				+ userName + ", clientId=" + clientId + ", authentication=" + authentication + ", refreshToken="
				+ refreshToken + ", ipAddress=" + ipAddress + "]";
	}

	public String getAuthId() {
		return authId;
	}

	public void setAuthId(String authId) {
		this.authId = authId;
	}

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public String getTokenData() {
		return tokenData;
	}

	public void setTokenData(String tokenData) {
		this.tokenData = tokenData;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getAuthentication() {
		return authentication;
	}

	public void setAuthentication(String authentication) {
		this.authentication = authentication;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public String getIpAddress() {
		return ipAddress;
	}

	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

}
