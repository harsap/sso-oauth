package com.tdi.sso.model;


public class Roles {
	private Integer idRoles;
	private String nama;
	private String keterangan; 

	
 

	public Roles(Integer idRoles, String nama, String keterangan) {
		super();
		this.idRoles = idRoles;
		this.nama = nama;
		this.keterangan = keterangan;
	}

	public Integer getIdRoles() {
		return idRoles;
	}

	public void setIdRoles(Integer idRoles) {
		this.idRoles = idRoles;
	}

	public String getNama() {
		return nama;
	}

	public void setNama(String nama) {
		this.nama = nama;
	}

	public String getKeterangan() {
		return keterangan;
	}

	public void setKeterangan(String keterangan) {
		this.keterangan = keterangan;
	}

}
