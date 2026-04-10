package com.devpath.domain.learning.entity;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "assignment_reference_files")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AssignmentReferenceFile {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "reference_file_id")
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "assignment_id", nullable = false)
  private Assignment assignment;

  @Column(name = "file_name", nullable = false, length = 255)
  private String fileName;

  @Column(name = "content_type", length = 120)
  private String contentType;

  @Column(name = "file_size", nullable = false)
  private Long fileSize;

  @Column(name = "display_order", nullable = false)
  private Integer displayOrder;

  @Lob
  @Basic(fetch = FetchType.LAZY)
  @Column(name = "file_data")
  private byte[] fileData;

  @Builder
  public AssignmentReferenceFile(
      Assignment assignment,
      String fileName,
      String contentType,
      Long fileSize,
      Integer displayOrder,
      byte[] fileData) {
    this.assignment = assignment;
    this.fileName = fileName;
    this.contentType = contentType;
    this.fileSize = fileSize == null ? 0L : fileSize;
    this.displayOrder = displayOrder == null ? 0 : displayOrder;
    this.fileData = fileData;
  }

  void assignAssignment(Assignment assignment) {
    this.assignment = assignment;
  }
}
