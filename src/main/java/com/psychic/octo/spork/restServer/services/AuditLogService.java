package com.psychic.octo.spork.restServer.services;

import com.psychic.octo.spork.restServer.models.AuditLog;
import com.psychic.octo.spork.restServer.models.Note;

import java.util.List;

public interface AuditLogService {

    public void logNoteCreation(String username, Note note);

    public void logNoteUpdate(String username, Note note);

    public void logNoteDeletion(String username, Long noteId);

    List<AuditLog> getAllAuditLogs();

    List<AuditLog> getAuditLogsForNoteId(Long id);
}
