package com.innowise.authenticationservice.mapper;

import com.innowise.authenticationservice.dto.CredentialResponseDto;
import com.innowise.authenticationservice.entity.Credential;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface CredentialMapper {
    CredentialResponseDto toDto(Credential credential);
}
