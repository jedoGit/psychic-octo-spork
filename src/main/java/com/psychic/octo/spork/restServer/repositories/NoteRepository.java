package com.psychic.octo.spork.restServer.repositories;

import com.psychic.octo.spork.restServer.models.Note;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface NoteRepository extends JpaRepository<Note, Long> {
    List<Note> findByOwnerUsername(String ownerUsername);
}
