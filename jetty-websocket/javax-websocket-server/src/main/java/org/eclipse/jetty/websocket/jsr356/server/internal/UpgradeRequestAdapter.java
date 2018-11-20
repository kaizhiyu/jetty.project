//
//  ========================================================================
//  Copyright (c) 1995-2018 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.websocket.jsr356.server.internal;

import org.eclipse.jetty.websocket.jsr356.UpgradeRequest;
import org.eclipse.jetty.websocket.servlet.ServletUpgradeRequest;

import java.net.URI;
import java.security.Principal;

public class UpgradeRequestAdapter implements UpgradeRequest
{
    private final ServletUpgradeRequest servletRequest;

    public UpgradeRequestAdapter(ServletUpgradeRequest servletRequest)
    {
        this.servletRequest = servletRequest;
    }

    @Override
    public Principal getUserPrincipal()
    {
        return servletRequest.getUserPrincipal();
    }

    @Override
    public URI getRequestURI()
    {
        return this.servletRequest.getRequestURI();
    }
}