package com.tdi.sso.model;

import java.sql.Timestamp;
import java.util.List;

public class User  {
 
	 
	private String id;
    private String username;
    private String email;
    private String password;
    private boolean active;
    private boolean locked;
    private boolean sudo;
    private boolean alwaysActive;
    private Integer loginFailedTimes;
    private String createdBy;
    private Timestamp createdDate;
    private String lastUpdateBy;
    private Timestamp lastUpdateDate;
    private List<Roles> listRoles;
    
    private UserIdentity userIdentity;
    
    public User() {
    	super();
    }
    public User(String username,   UserIdentity userIdentity) {
		 this.username = username; 
		this.userIdentity = userIdentity;
	}
	public User(String username, List<Roles> listRoles, UserIdentity userIdentity) {
		 this.username = username;
		this.listRoles = listRoles;
		this.userIdentity = userIdentity;
	}
	public UserIdentity getUserIdentity() {
		return userIdentity;
	}
	public void setUserIdentity(UserIdentity userIdentity) {
		this.userIdentity = userIdentity;
	}
	public List<Roles> getListRoles() {
		return listRoles;
	}
	public void setListRoles(List<Roles> listRoles) {
		this.listRoles = listRoles;
	}
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public boolean isActive() {
		return active;
	}
	public void setActive(boolean active) {
		this.active = active;
	}
	public boolean isLocked() {
		return locked;
	}
	public void setLocked(boolean locked) {
		this.locked = locked;
	}
	public boolean isSudo() {
		return sudo;
	}
	public void setSudo(boolean sudo) {
		this.sudo = sudo;
	}
	public boolean isAlwaysActive() {
		return alwaysActive;
	}
	public void setAlwaysActive(boolean alwaysActive) {
		this.alwaysActive = alwaysActive;
	}
	public Integer getLoginFailedTimes() {
		return loginFailedTimes;
	}
	public void setLoginFailedTimes(Integer loginFailedTimes) {
		this.loginFailedTimes = loginFailedTimes;
	}
	public String getCreatedBy() {
		return createdBy;
	}
	public void setCreatedBy(String createdBy) {
		this.createdBy = createdBy;
	}
	public Timestamp getCreatedDate() {
		return createdDate;
	}
	public void setCreatedDate(Timestamp createdDate) {
		this.createdDate = createdDate;
	}
	public String getLastUpdateBy() {
		return lastUpdateBy;
	}
	public void setLastUpdateBy(String lastUpdateBy) {
		this.lastUpdateBy = lastUpdateBy;
	}
	public Timestamp getLastUpdateDate() {
		return lastUpdateDate;
	}
	public void setLastUpdateDate(Timestamp lastUpdateDate) {
		this.lastUpdateDate = lastUpdateDate;
	}
    
    
}
