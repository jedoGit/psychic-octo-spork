package com.psychic.octo.spork.restServer.controller;

import com.psychic.octo.spork.restServer.models.AuditLog;
import com.psychic.octo.spork.restServer.services.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
//@PreAuthorize("hasRole('ROLE_ADMIN')") // Enabled in the defaultSecurityFilterChain() using requestMatchers
public class AuditLogController {

    @Autowired
    AuditLogService auditLogService;

    @GetMapping
    public List<AuditLog> getAllAuditLogs() {
        return auditLogService.getAllAuditLogs();
    }

    @GetMapping("/note/{id}")
    public List<AuditLog> getNoteAuditLogs(@PathVariable Long id) {
        return auditLogService.getAuditLogsForNoteId(id);
    }
}
