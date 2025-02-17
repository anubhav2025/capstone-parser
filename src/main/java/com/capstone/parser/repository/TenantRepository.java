package com.capstone.parser.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.capstone.parser.model.Tenant;


@Repository
public interface TenantRepository extends JpaRepository<Tenant, Long> {

    Tenant findByTenantId(String tenantId);
}
